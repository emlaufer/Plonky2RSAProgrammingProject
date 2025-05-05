import { User } from '../types';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Avatar, AvatarFallback, AvatarImage } from './ui/avatar';
import { ScrollArea } from './ui/scroll-area';
import { cn } from '@/lib/utils';

interface UserListProps {
  users: User[];
  isLoading?: boolean;
}

const UserList = ({ users, isLoading = false }: UserListProps) => {
  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <CardTitle className="flex justify-between items-center">
          <span>Users</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[calc(100vh-300px)] px-4 pb-4">
          {isLoading ? (
            <div className="flex justify-center items-center h-full">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-t-transparent border-gray-400"></div>
              <span className="ml-2 text-muted-foreground">Loading users...</span>
            </div>
          ) : (
            <div className="space-y-2">
              {users.map((user) => {
                const initials = user.name
                  .split(' ')
                  .map((n) => n[0])
                  .join('')
                  .toUpperCase();

                return (
                  <div
                    key={user._id}
                    className={cn(
                      'flex items-center gap-3 rounded-md p-2 cursor-pointer transition-colors',
                      'hover:bg-muted',
                    )}
                  >
                    <Avatar className="h-9 w-9 relative">
                      <AvatarImage src={user.avatar} alt={user.name} />
                      <AvatarFallback>{initials}</AvatarFallback>
                    </Avatar>
                    <div className="flex flex-col overflow-hidden">
                      <span className="text-sm font-medium truncate">{user.name}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default UserList;
