import express from 'express';
import User from '../models/User';

const router = express.Router();

/**
 * Get all users
 * @route GET /users
 */
router.get('/users', async (_req, res) => {
  try {
    const users = await User.find();
    res.status(200).json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * Update user's public key
 * @route PUT /users/:id/publickey
 * @body {publicKey}
 */
router.put('/users/:id/publickey', async (req, res) => {
  try {
    const { id } = req.params;
    const { publicKey } = req.body;

    if (!publicKey) {
      return res.status(400).json({ error: 'Public key is required' });
    }

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.publicKey = publicKey;
    await user.save();

    res.status(200).json(user);
  } catch (err) {
    console.error('Error updating user public key:', err);
    res.status(500).json({ error: 'Failed to update user public key' });
  }
});

export default router;
