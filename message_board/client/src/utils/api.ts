import axios from 'axios';
import { Post, User, Circuit } from '../types';

const API_URL = 'http://localhost:5000';
const CGI_URL = 'cgi-bin';

// Set this flag to true to use the CGI-based API, or false to use the original API
const USE_CGI_API = true;

// Create an axios instance with default settings
const api = axios.create({
  baseURL: USE_CGI_API ? CGI_URL : API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Post-related API calls
export async function fetchPosts(): Promise<Post[]> {
  try {
    const endpoint = USE_CGI_API ? '/messages.php' : '/messages';
    const response = await api.get(endpoint);
    return response.data;
  } catch (error) {
    console.error('Error fetching posts:', error);
    throw error;
  }
}

export async function createPost(post: { userIds: number[]; message: string }): Promise<Post> {
  try {
    const endpoint = USE_CGI_API ? '/messages.php' : '/messages';
    const response = await api.post(endpoint, post);
    return response.data;
  } catch (error) {
    console.error('Error creating post:', error);
    throw error;
  }
}

// User-related API calls
export async function fetchUsers(): Promise<User[]> {
  try {
    const endpoint = USE_CGI_API ? '/users.php' : '/users';
    const response = await api.get(endpoint);
    return response.data;
  } catch (error) {
    console.error('Error fetching users:', error);
    throw error;
  }
}

export async function createUser(post: Omit<User, '_id'>): Promise<User> {
  try {
    const endpoint = USE_CGI_API ? '/users.php' : '/users';
    const response = await api.post(endpoint, post);
    return response.data;
  } catch (error) {
    console.error('Error creating user:', error);
    throw error;
  }
}

// Circuit-related API calls
export async function fetchCircuits(): Promise<Omit<Circuit, 'circuit' & 'verifier_only'>[]> {
  try {
    const endpoint = USE_CGI_API ? '/circuits.php' : '/circuits';
    const response = await api.get(endpoint);
    console.log(response);
    return response.data;
  } catch (error) {
    console.error('Error fetching circuits:', error);
    throw error;
  }
}

export async function createCircuit(post: Omit<Circuit, '_id'>): Promise<Circuit> {
  try {
    const endpoint = USE_CGI_API ? '/circuits.php' : '/circuits';
    const response = await api.post(endpoint, post);
    return response.data;
  } catch (error) {
    console.error('Error creating circuit:', error);
    throw error;
  }
}

export async function fetchUserById(id: string): Promise<User> {
  try {
    const endpoint = USE_CGI_API ? `/users.php/` : `/users/${id}`;
    const response = await api.get(endpoint);
    return response.data;
  } catch (error) {
    console.error(`Error fetching user with ID ${id}:`, error);
    throw error;
  }
}
