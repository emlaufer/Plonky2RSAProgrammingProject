export interface User {
  _id: number;
  name: string;
  avatar: string;
  public_key: string;
}

export interface Post {
  _id: number;
  userIds: number[];
  message: string;
  timestamp: string;
}

export interface Circuit {
  _id: number;
  name: string;
  circuit: string;
  verifier_circuit_data: string;
}
