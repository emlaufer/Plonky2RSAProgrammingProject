import { formatDistanceToNow } from '../utils/dateUtils';
import { Post, User } from '../types';
import { Card, CardContent } from './ui/card';
import { Avatar, AvatarFallback, AvatarImage } from './ui/avatar';
import { AvatarGroup } from './ui/avatar-group';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';

interface PostItemProps {
  post: Post;
  users: User[];
}

const PostItem = ({ post, users }: PostItemProps) => {
  const { userIds, message, timestamp } = post;

  // Get all authors of this post
  const authors = users.filter((user) => userIds.includes(user._id));

  // For display in the post header
  const primaryAuthor = authors[0] || {
    name: 'Unknown User',
    avatar: 'https://i.pravatar.cc/150?img=0',
  };
  const otherAuthors = authors.slice(1);

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase();
  };

  return (
    <Card className="overflow-hidden transition-all hover:shadow-md">
      <CardContent className="p-4">
        <div className="flex items-start space-x-4">
          <div>
            {authors.length === 1 ? (
              <Avatar className="h-10 w-10">
                <AvatarImage src={primaryAuthor.avatar} alt={primaryAuthor.name} />
                <AvatarFallback>{getInitials(primaryAuthor.name)}</AvatarFallback>
              </Avatar>
            ) : (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div>
                      <AvatarGroup limit={3}>
                        {authors.map((author) => (
                          <Avatar key={author._id} className="h-8 w-8 border-2 border-background">
                            <AvatarImage src={author.avatar} alt={author.name} />
                            <AvatarFallback>{getInitials(author.name)}</AvatarFallback>
                          </Avatar>
                        ))}
                      </AvatarGroup>
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <div className="text-xs">{authors.map((author) => author.name).join(', ')}</div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex justify-between items-center mb-1">
              <div>
                {authors.length === 1 ? (
                  <h3 className="text-sm font-medium">{primaryAuthor.name}</h3>
                ) : (
                  <h3 className="text-sm font-medium">
                    {primaryAuthor.name}
                    <span className="text-muted-foreground font-normal">
                      {` with ${otherAuthors.length} ${otherAuthors.length === 1 ? 'other' : 'others'}`}
                    </span>
                  </h3>
                )}
              </div>
              <span className="text-xs text-muted-foreground">
                {formatDistanceToNow(new Date(timestamp))}
              </span>
            </div>
            <p className="text-sm whitespace-pre-line break-words">{message}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default PostItem;
