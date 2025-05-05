import { useState, useEffect } from 'react';
import MessageBoard from './components/MessageBoard';
import { ThemeProvider } from './components/ThemeProvider';
import { Post, User, Circuit } from './types';
import {
  fetchPosts,
  createPost,
  fetchUsers,
  createUser,
  fetchCircuits,
  createCircuit,
} from './utils/api';
import axios from 'axios';

function App() {
  const [posts, setPosts] = useState<Post[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [circuits, setCircuits] = useState<Circuit[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch both posts and users when component mounts
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const [fetchedPosts, fetchedUsers, fetchedCircuits] = await Promise.all([
          fetchPosts(),
          fetchUsers(),
          fetchCircuits(),
        ]);

        setPosts(fetchedPosts);
        setUsers(fetchedUsers.sort((a, b) => a.name.localeCompare(b.name)));
        setCircuits(fetchedCircuits);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch data', err);
        setError('Failed to load data. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const addCircuit = async (newCircuit: Omit<Circuit, '_id'>) => {
    try {
      const createdCircuit = await createCircuit(newCircuit);
      setCircuits([createdCircuit, ...circuits]);
      setError(null);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        console.error('Failed to add circuit', err);
        if (err.response?.data?.error === 'A circuit with this name already exists') {
          setError('A circuit with this name already exists. Please choose a different name.');
        } else {
          setError('Failed to add circuit. Please try again later.');
        }
      } else {
        console.error('Unexpected error', err);
        setError('An unexpected error occurred. Please try again later.');
      }
    }
  };

  const addUser = async (newUser: Omit<User, '_id'>) => {
    try {
      const createdUser = await createUser(newUser);
      setUsers([createdUser, ...users].sort((a, b) => a.name.localeCompare(b.name)));
      setError(null);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        console.error('Failed to add user', err);
        setError('Failed to add user. Please try again later.');
      } else {
        console.error('Unexpected error', err);
        setError('An unexpected error occurred. Please try again later.');
      }
    }
  };

  const addPost = async (newPost: Omit<Post, '_id' | 'timestamp'>) => {
    try {
      console.log('adding post', newPost);
      const createdPost = await createPost(newPost);
      setPosts([createdPost, ...posts]);
      setError(null);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        console.error('Failed to add post', err);
        if (err.response?.data?.error === 'Proof verification failed') {
          setError('Failed to add message: invalid proof.');
        } else {
          setError('Failed to add message. Please try again later.');
        }
      } else {
        console.error('Unexpected error', err);
        setError('An unexpected error occurred. Please try again later.');
      }
    }
  };
  console.log(circuits);

  return (
    <ThemeProvider defaultTheme="light" storageKey="message-board-theme">
      <div className="min-h-screen bg-background">
        <div className="container mx-auto py-4 px-4 sm:px-6 lg:px-8">
          <MessageBoard
            posts={posts}
            users={users}
            circuits={circuits}
            onAddPost={addPost}
            onAddUser={addUser}
            onAddCircuit={addCircuit}
            error={error}
            setError={setError}
            isLoading={loading}
          />
        </div>
      </div>
    </ThemeProvider>
  );
}

export default App;
