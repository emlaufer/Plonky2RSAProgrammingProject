import mongoose from 'mongoose';

export interface IMessage extends mongoose.Document {
  userIds: string[];
  message: string;
  timestamp: string;
  proof?: string; // Plonky2 proof
  verifierData?: string; // Verification data
  common?: string; // Common input for verification
  id: string;
}

const messageSchema = new mongoose.Schema(
  {
    userIds: [String],
    message: String,
    timestamp: { type: String, default: () => new Date().toISOString() },
    proof: String, // Store the Plonky2 proof
    verifierData: String, // Store verification data
    common: String, // Store common verification input
  },
  {
    timestamps: true,
  },
);

export default mongoose.model<IMessage>('Message', messageSchema);
