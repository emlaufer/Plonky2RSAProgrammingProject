import { useState } from 'react';
import { Post, User, Circuit } from '../types';
import PostItem from './PostItem';
import UserList from './UserList';
import PostForm from './PostForm';
import UserSignupDialog from './UserSignupDialog';
import CircuitUploadDialog from './CircuitUploadDialog';
import Pagination from './Pagination';
import { ModeToggle } from './ModeToggle';
import { Button } from './ui/button';
import { UserPlus, Cpu } from 'lucide-react';

interface MessageBoardProps {
  posts: Post[];
  users: User[];
  circuits: Circuit[];
  onAddPost: (post: Omit<Post, '_id' | 'timestamp'>) => void;
  onAddUser: (post: Omit<User, '_id'>) => void;
  onAddCircuit: (post: Omit<Circuit, '_id'>) => void;
  error: String | null;
  setError?: (error: string | null) => void;
  isLoading?: boolean;
}

const POSTS_PER_PAGE = 10;

const MessageBoard = ({
  posts,
  users,
  circuits,
  onAddPost,
  onAddUser,
  onAddCircuit,
  error = null,
  setError = () => {},
  isLoading = false,
}: MessageBoardProps) => {
  const [currentPage, setCurrentPage] = useState(1);
  const [signupDialogOpen, setSignupDialogOpen] = useState(false);
  const [circuitDialogOpen, setCircuitDialogOpen] = useState(false);

  // TODO: fix
  const totalPages = Math.ceil(posts.length / POSTS_PER_PAGE);
  const indexOfLastPost = currentPage * POSTS_PER_PAGE;
  const indexOfFirstPost = indexOfLastPost - POSTS_PER_PAGE;
  const currentPosts = posts.slice(indexOfFirstPost, indexOfLastPost);

  const handleAddPost = (post: Omit<Post, '_id' | 'timestamp'>) => {
    onAddPost(post);

    // Reset to first page when new post is added
    setCurrentPage(1);
  };

  const handlePageChange = (pageNumber: number) => {
    setCurrentPage(pageNumber);
    // Scroll to top of posts section
    document.getElementById('posts-section')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="flex flex-col gap-8">
      {/* Sticky container for navigation bar and error message */}
      <div className="sticky top-0 z-20 bg-background border-b">
        {/* Top navigation bar - always visible */}
        <div className="flex justify-between items-center pb-2 pt-2">
          <h1 className="text-xl font-bold">Message Board</h1>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCircuitDialogOpen(true)}
              className="flex items-center gap-1"
            >
              <Cpu className="h-4 w-4" />
              <span className="hidden sm:inline">Upload Circuit</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSignupDialogOpen(true)}
              className="flex items-center gap-1"
            >
              <UserPlus className="h-4 w-4" />
              <span className="hidden sm:inline">Sign Up</span>
            </Button>
            <ModeToggle />
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            <div className="flex justify-between items-center">
              <span className="block sm:inline">{error}</span>
              <button className="ml-4 text-sm underline" onClick={() => setError(null)}>
                Dismiss
              </button>
            </div>
          </div>
        )}
      </div>
      <div className="flex flex-col lg:flex-row gap-8">
        {/* Sidebar with users - visible only on large screens */}
        <div className="hidden lg:block lg:w-1/4 space-y-6">
          <div>
            <UserList users={users} isLoading={isLoading} />
          </div>
        </div>

        {/* Main content */}
        <div className="lg:w-3/4 space-y-8">
          <PostForm users={users} circuits={circuits} onAddPost={handleAddPost} />

          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Recent Messages</h2>
            {isLoading ? (
              <div className="text-center py-8">
                <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border"></div>
                <p className="mt-2 text-muted-foreground">Loading messages...</p>
              </div>
            ) : posts.length > 0 ? (
              <>
                <div className="space-y-4">
                  {currentPosts.map((post) => (
                    <PostItem key={post._id} post={post} users={users} />
                  ))}
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="flex justify-center mt-6">
                    <Pagination
                      currentPage={currentPage}
                      totalPages={totalPages}
                      onPageChange={handlePageChange}
                    />
                  </div>
                )}

                {/* Page indicator */}
                {totalPages > 1 && (
                  <div className="text-center text-sm text-muted-foreground">
                    Showing {indexOfFirstPost + 1}-{Math.min(indexOfLastPost, posts.length)} of{' '}
                    {posts.length} posts
                  </div>
                )}
              </>
            ) : (
              <p>No messages yet. Be the first to post!</p>
            )}
          </div>
        </div>
        {/* User Signup Dialog */}
        <UserSignupDialog
          open={signupDialogOpen}
          onOpenChange={setSignupDialogOpen}
          onAddUser={onAddUser}
        />
        {/* User Signup Dialog */}
        <CircuitUploadDialog
          open={circuitDialogOpen}
          onOpenChange={setCircuitDialogOpen}
          onAddCircuit={onAddCircuit}
        />
      </div>
    </div>
  );
};

export default MessageBoard;
