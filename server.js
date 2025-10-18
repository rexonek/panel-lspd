// ============================================
// server.js - Main Express Server
// ============================================

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'lspd_badges',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ============================================
// MIDDLEWARE - Auth
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ============================================
// SERVICES - Badge Logic
// ============================================

class BadgeService {
  static async getMemberRank(memberId) {
    const [rows] = await pool.query(
      'SELECT rank_id, badge_number FROM members WHERE id = ?',
      [memberId]
    );
    return rows[0] || null;
  }

  static async hasBadge(memberId) {
    const [rows] = await pool.query(
      'SELECT badge_number FROM members WHERE id = ? AND badge_number IS NOT NULL',
      [memberId]
    );
    return rows.length > 0;
  }

  static async getRankInfo(rankId) {
    const [rows] = await pool.query(
      'SELECT * FROM ranks WHERE id = ?',
      [rankId]
    );
    return rows[0] || null;
  }

  static async getFirstFreeBadge(rankId) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Get rank info
      const [rankRows] = await conn.query(
        'SELECT badge_min, badge_max, max_slots FROM ranks WHERE id = ?',
        [rankId]
      );

      if (!rankRows[0] || !rankRows[0].badge_min) {
        await conn.rollback();
        return { success: false, error: 'This rank does not have badges assigned' };
      }

      const { badge_min, badge_max, max_slots } = rankRows[0];

      // Check if rank is full
      const [countRows] = await conn.query(
        'SELECT COUNT(*) as count FROM members WHERE rank_id = ?',
        [rankId]
      );

      if (countRows[0].count >= max_slots) {
        await conn.rollback();
        return { success: false, error: 'Rank is full (max slots reached)' };
      }

      // Find first free badge
      const [badgeRows] = await conn.query(
        `SELECT badge_number FROM badges 
         WHERE rank_id = ? AND assigned_to IS NULL 
         ORDER BY badge_number ASC 
         LIMIT 1 FOR UPDATE`,
        [rankId]
      );

      if (badgeRows.length === 0) {
        await conn.rollback();
        return { success: false, error: 'No free badges available for this rank' };
      }

      const badgeNumber = badgeRows[0].badge_number;
      await conn.commit();

      return { success: true, badgeNumber };
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  }

  static async assignBadge(memberId, badgeNumber, assignedBy = null) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Get member's rank
      const [memberRows] = await conn.query(
        'SELECT rank_id FROM members WHERE id = ?',
        [memberId]
      );

      if (!memberRows[0]) {
        await conn.rollback();
        return { success: false, error: 'Member not found' };
      }

      const rankId = memberRows[0].rank_id;

      // Update badge table
      const [updateBadge] = await conn.query(
        `UPDATE badges 
         SET assigned_to = ?, assigned_at = NOW(), assigned_by = ?
         WHERE badge_number = ? AND rank_id = ? AND assigned_to IS NULL`,
        [memberId, assignedBy, badgeNumber, rankId]
      );

      if (updateBadge.affectedRows === 0) {
        await conn.rollback();
        return { success: false, error: 'Badge already assigned or invalid' };
      }

      // Update member table
      await conn.query(
        'UPDATE members SET badge_number = ? WHERE id = ?',
        [badgeNumber, memberId]
      );

      await conn.commit();
      return { success: true, badgeNumber };
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  }

  static async releaseBadge(badgeNumber) {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Release badge
      await conn.query(
        `UPDATE badges 
         SET assigned_to = NULL, released_at = NOW()
         WHERE badge_number = ?`,
        [badgeNumber]
      );

      // Update member
      await conn.query(
        'UPDATE members SET badge_number = NULL WHERE badge_number = ?',
        [badgeNumber]
      );

      await conn.commit();
      return { success: true };
    } catch (error) {
      await conn.rollback();
      throw error;
    } finally {
      conn.release();
    }
  }
}

// ============================================
// ROUTES - Authentication
// ============================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const [users] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// ROUTES - Badges
// ============================================

// /nowaodznaka command - Assign new badge
app.post('/api/badges/assign', authenticateToken, async (req, res) => {
  try {
    const { memberId } = req.body;

    if (!memberId) {
      return res.status(400).json({ error: 'Member ID required' });
    }

    // Check if member exists
    const memberRank = await BadgeService.getMemberRank(memberId);
    if (!memberRank) {
      return res.status(404).json({ error: 'Member not found' });
    }

    // Check if member already has a badge
    if (await BadgeService.hasBadge(memberId)) {
      return res.status(400).json({ 
        error: 'Masz już odznakę przypisaną do swojego stopnia!' 
      });
    }

    // Check if rank has badges
    const rankInfo = await BadgeService.getRankInfo(memberRank.rank_id);
    if (!rankInfo.badge_min) {
      return res.status(400).json({ 
        error: 'Your rank does not have badges (leadership position)' 
      });
    }

    // Get first free badge
    const freeBadgeResult = await BadgeService.getFirstFreeBadge(memberRank.rank_id);
    
    if (!freeBadgeResult.success) {
      if (freeBadgeResult.error.includes('full')) {
        return res.status(409).json({ 
          error: 'Brak wolnych odznak dla tego stopnia, skontaktuj się z kadrą.' 
        });
      }
      return res.status(400).json({ error: freeBadgeResult.error });
    }

    // Assign badge
    const assignResult = await BadgeService.assignBadge(
      memberId, 
      freeBadgeResult.badgeNumber,
      req.user.id
    );

    if (!assignResult.success) {
      return res.status(500).json({ error: assignResult.error });
    }

    res.json({
      success: true,
      message: `Badge #${assignResult.badgeNumber} assigned successfully`,
      badgeNumber: assignResult.badgeNumber
    });

  } catch (error) {
    console.error('Badge assignment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get free badges for a rank
app.get('/api/badges/free', authenticateToken, async (req, res) => {
  try {
    const { rank_id } = req.query;

    if (!rank_id) {
      return res.status(400).json({ error: 'Rank ID required' });
    }

    const [badges] = await pool.query(
      `SELECT badge_number FROM badges 
       WHERE rank_id = ? AND assigned_to IS NULL 
       ORDER BY badge_number ASC`,
      [rank_id]
    );

    res.json({ badges: badges.map(b => b.badge_number) });
  } catch (error) {
    console.error('Get free badges error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// ROUTES - Ranks
// ============================================

app.get('/api/ranks', authenticateToken, async (req, res) => {
  try {
    const [ranks] = await pool.query(`
      SELECT 
        r.*,
        COUNT(CASE WHEN m.id IS NOT NULL THEN 1 END) as current_members,
        COUNT(CASE WHEN b.assigned_to IS NULL THEN 1 END) as free_badges
      FROM ranks r
      LEFT JOIN members m ON r.id = m.rank_id
      LEFT JOIN badges b ON r.id = b.rank_id
      GROUP BY r.id
      ORDER BY r.priority
    `);

    res.json({ ranks });
  } catch (error) {
    console.error('Get ranks error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/ranks/:id', authenticateToken, async (req, res) => {
  try {
    const [ranks] = await pool.query(
      'SELECT * FROM ranks WHERE id = ?',
      [req.params.id]
    );

    if (ranks.length === 0) {
      return res.status(404).json({ error: 'Rank not found' });
    }

    res.json({ rank: ranks[0] });
  } catch (error) {
    console.error('Get rank error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// ROUTES - Members
// ============================================

app.get('/api/members', authenticateToken, async (req, res) => {
  try {
    const { rank_id, search } = req.query;
    let query = `
      SELECT 
        m.id,
        m.character_name,
        m.discord_id,
        m.badge_number,
        m.created_at,
        m.updated_at,
        r.rank_name,
        r.priority,
        b.assigned_at,
        u.username as assigned_by_username
      FROM members m
      JOIN ranks r ON m.rank_id = r.id
      LEFT JOIN badges b ON m.badge_number = b.badge_number
      LEFT JOIN users u ON b.assigned_by = u.id
      WHERE 1=1
    `;
    const params = [];

    if (rank_id) {
      query += ' AND m.rank_id = ?';
      params.push(rank_id);
    }

    if (search) {
      query += ' AND (m.character_name LIKE ? OR m.badge_number LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY r.priority, m.badge_number';

    const [members] = await pool.query(query, params);

    res.json({ members });
  } catch (error) {
    console.error('Get members error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/members/:id', authenticateToken, async (req, res) => {
  try {
    const [members] = await pool.query(`
      SELECT 
        m.*,
        r.rank_name,
        r.priority,
        r.badge_min,
        r.badge_max
      FROM members m
      JOIN ranks r ON m.rank_id = r.id
      WHERE m.id = ?
    `, [req.params.id]);

    if (members.length === 0) {
      return res.status(404).json({ error: 'Member not found' });
    }

    // Get promotion history
    const [promotions] = await pool.query(`
      SELECT 
        p.*,
        r1.rank_name as from_rank_name,
        r2.rank_name as to_rank_name,
        u.username as changed_by_username
      FROM promotions p
      JOIN ranks r1 ON p.from_rank_id = r1.id
      JOIN ranks r2 ON p.to_rank_id = r2.id
      LEFT JOIN users u ON p.changed_by = u.id
      WHERE p.member_id = ?
      ORDER BY p.changed_at DESC
    `, [req.params.id]);

    res.json({ 
      member: members[0],
      promotions 
    });
  } catch (error) {
    console.error('Get member error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/members', authenticateToken, async (req, res) => {
  try {
    const { character_name, discord_id, rank_id } = req.body;

    if (!character_name || !rank_id) {
      return res.status(400).json({ error: 'Character name and rank are required' });
    }

    // Check if discord_id already exists
    if (discord_id) {
      const [existing] = await pool.query(
        'SELECT id FROM members WHERE discord_id = ?',
        [discord_id]
      );
      if (existing.length > 0) {
        return res.status(409).json({ error: 'Discord ID already exists' });
      }
    }

    // Check rank capacity
    const [rankInfo] = await pool.query(
      'SELECT max_slots FROM ranks WHERE id = ?',
      [rank_id]
    );

    if (rankInfo[0] && rankInfo[0].max_slots) {
      const [count] = await pool.query(
        'SELECT COUNT(*) as count FROM members WHERE rank_id = ?',
        [rank_id]
      );
      if (count[0].count >= rankInfo[0].max_slots) {
        return res.status(409).json({ error: 'Rank is full' });
      }
    }

    const [result] = await pool.query(
      'INSERT INTO members (character_name, discord_id, rank_id) VALUES (?, ?, ?)',
      [character_name, discord_id, rank_id]
    );

    res.status(201).json({
      success: true,
      memberId: result.insertId
    });
  } catch (error) {
    console.error('Create member error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/members/:id/rank', authenticateToken, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { new_rank_id, note } = req.body;
    const memberId = req.params.id;

    if (!new_rank_id) {
      return res.status(400).json({ error: 'New rank ID required' });
    }

    await conn.beginTransaction();

    // Get current member info
    const [memberRows] = await conn.query(
      'SELECT rank_id, badge_number FROM members WHERE id = ?',
      [memberId]
    );

    if (memberRows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Member not found' });
    }

    const oldRankId = memberRows[0].rank_id;
    const oldBadge = memberRows[0].badge_number;

    // Get new rank info
    const [newRankRows] = await conn.query(
      'SELECT badge_min, badge_max, max_slots FROM ranks WHERE id = ?',
      [new_rank_id]
    );

    if (newRankRows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'New rank not found' });
    }

    const newRankInfo = newRankRows[0];
    let newBadge = null;

    // Check if new rank has badges
    if (newRankInfo.badge_min) {
      // Check rank capacity
      const [count] = await conn.query(
        'SELECT COUNT(*) as count FROM members WHERE rank_id = ?',
        [new_rank_id]
      );

      if (count[0].count >= newRankInfo.max_slots) {
        await conn.rollback();
        return res.status(409).json({ error: 'New rank is full' });
      }

      // Check if current badge is in new rank range
      if (oldBadge && oldBadge >= newRankInfo.badge_min && oldBadge <= newRankInfo.badge_max) {
        // Check if badge is available in new rank
        const [badgeCheck] = await conn.query(
          `SELECT badge_number FROM badges 
           WHERE badge_number = ? AND rank_id = ? AND (assigned_to IS NULL OR assigned_to = ?)`,
          [oldBadge, new_rank_id, memberId]
        );

        if (badgeCheck.length > 0) {
          newBadge = oldBadge; // Keep same badge number
        }
      }

      // If badge not in range or not available, get new one
      if (!newBadge) {
        // Release old badge if exists
        if (oldBadge) {
          await conn.query(
            'UPDATE badges SET assigned_to = NULL, released_at = NOW() WHERE badge_number = ?',
            [oldBadge]
          );
        }

        // Get first free badge in new rank
        const [freeBadges] = await conn.query(
          `SELECT badge_number FROM badges 
           WHERE rank_id = ? AND assigned_to IS NULL 
           ORDER BY badge_number ASC LIMIT 1 FOR UPDATE`,
          [new_rank_id]
        );

        if (freeBadges.length === 0) {
          await conn.rollback();
          return res.status(409).json({ error: 'No free badges in new rank' });
        }

        newBadge = freeBadges[0].badge_number;

        // Assign new badge
        await conn.query(
          `UPDATE badges 
           SET assigned_to = ?, assigned_at = NOW(), assigned_by = ?
           WHERE badge_number = ?`,
          [memberId, req.user.id, newBadge]
        );
      }
    } else {
      // New rank doesn't have badges (leadership)
      if (oldBadge) {
        await conn.query(
          'UPDATE badges SET assigned_to = NULL, released_at = NOW() WHERE badge_number = ?',
          [oldBadge]
        );
      }
    }

    // Update member
    await conn.query(
      'UPDATE members SET rank_id = ?, badge_number = ? WHERE id = ?',
      [new_rank_id, newBadge, memberId]
    );

    // Record promotion
    await conn.query(
      `INSERT INTO promotions (member_id, from_rank_id, to_rank_id, old_badge, new_badge, changed_by, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [memberId, oldRankId, new_rank_id, oldBadge, newBadge, req.user.id, note]
    );

    await conn.commit();

    res.json({
      success: true,
      newBadge,
      message: 'Rank updated successfully'
    });

  } catch (error) {
    await conn.rollback();
    console.error('Update rank error:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

app.delete('/api/members/:id', authenticateToken, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Get member's badge
    const [member] = await conn.query(
      'SELECT badge_number FROM members WHERE id = ?',
      [req.params.id]
    );

    if (member.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Member not found' });
    }

    // Release badge if exists
    if (member[0].badge_number) {
      await conn.query(
        'UPDATE badges SET assigned_to = NULL, released_at = NOW() WHERE badge_number = ?',
        [member[0].badge_number]
      );
    }

    // Delete member
    await conn.query('DELETE FROM members WHERE id = ?', [req.params.id]);

    await conn.commit();
    res.json({ success: true });

  } catch (error) {
    await conn.rollback();
    console.error('Delete member error:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    conn.release();
  }
});

// ============================================
// ROUTES - Statistics
// ============================================

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const [stats] = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM members) as total_members,
        (SELECT COUNT(*) FROM badges WHERE assigned_to IS NOT NULL) as badges_assigned,
        (SELECT COUNT(*) FROM badges WHERE assigned_to IS NULL) as badges_available,
        (SELECT COUNT(*) FROM ranks WHERE badge_min IS NOT NULL) as operational_ranks
    `);

    const [rankStats] = await pool.query(`
      SELECT 
        r.rank_name,
        r.max_slots,
        COUNT(m.id) as current_count
      FROM ranks r
      LEFT JOIN members m ON r.id = m.rank_id
      WHERE r.badge_min IS NOT NULL
      GROUP BY r.id
      ORDER BY r.priority
    `);

    res.json({
      overview: stats[0],
      rankStats
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`🚔 LSPD Badge System API running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
});
