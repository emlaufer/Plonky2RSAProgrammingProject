import express from 'express';
import Message from '../models/Message';
import User from '../models/User';
import verifyProof from '../plonky2';

const router = express.Router();

/**
 * Get all messages
 * @route GET /messages
 */
router.get('/messages', async (_req, res) => {
  try {
    const messages = await Message.find().sort({ timestamp: -1 });
    res.status(200).json(messages);
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

/**
 * Create a new message
 * @route POST /messages
 * @body {userIds, message, proof, verifierData, common}
 */
router.post('/messages', async (req, res) => {
  try {
    const { userIds, message, proof, verifierData, common } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0 || !message) {
      return res.status(400).json({ error: 'UserIds array and message are required' });
    }

    // Verify that users exist and have public keys registered
    const users = await User.find({ _id: { $in: userIds } });
    if (users.length !== userIds.length) {
      return res.status(400).json({ error: 'One or more users do not exist' });
    }

    // Verify the Plonky2 proof if provided
    if (proof && verifierData && common) {
      try {
        // Fetch public keys of the users
        const publicKeys = users.map((user) => user.publicKey || '').filter((key) => key !== ''); // Filter out empty keys
        publicKeys.sort(); // Ensure consistent order for verification
        //console.log('CHECKING PROOF:', proof, verifierData, common, message, publicKeys);
        const isValid = await verifyProof(proof, verifierData, common, message, publicKeys);
      } catch (error) {
        console.error('Error verifying proof:', error);
        return res.status(400).json({ error: 'Proof verification failed' });
      }
    }

    const newMessage = new Message({
      userIds,
      message,
      timestamp: new Date().toISOString(),
      proof,
      verifierData,
      common,
    });
    await newMessage.save();

    res.status(201).json(newMessage);
  } catch (err) {
    console.error('Error adding message:', err);
    res.status(500).json({ error: 'Failed to add message' });
  }
});

export default router;
