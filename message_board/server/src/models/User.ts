import mongoose from 'mongoose';

export interface IUser extends mongoose.Document {
  name: string;
  avatar: string;
  publicKey: string; // RSA public key for verification
  id: string;
}

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    avatar: { type: String },
    publicKey: { type: String, required: true }, // Store the user's RSA public key
  },
  {
    timestamps: true,
  },
);

export default mongoose.model<IUser>('User', userSchema);
