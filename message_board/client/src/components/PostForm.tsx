import { useState, useEffect } from 'react';
import { User, Circuit } from '../types';
import { Button } from './ui/button';
import { Textarea } from './ui/textarea';
import { Card, CardContent } from './ui/card';
import { Avatar, AvatarFallback, AvatarImage } from './ui/avatar';
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from './ui/multi-select';
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from './ui/select'; // Import Select components
import { verifyProofInputs } from '@/utils/plonky';

interface PostFormProps {
  users: User[];
  circuits: Circuit[];
  onAddPost: (post: {
    userIds: number[];
    message: string;
    proof: string;
    circuit_id: number;
  }) => void;
}

const PostForm = ({ users, circuits, onAddPost }: PostFormProps) => {
  const [message, setMessage] = useState('');
  const [selectedUserIds, setSelectedUserIds] = useState<number[]>([]);
  const [selectedCircuit, setSelectedCircuit] = useState<number | null>(null); // State for selected circuit
  const [error, setError] = useState('');
  const [proofFileName, setProofFileName] = useState<string>('');
  const [proof, setProof] = useState<string>('');

  const selectedUsers = users.filter((user) => selectedUserIds.includes(user._id));

  // NOTE: We used to support client size verification...however this means we need to give circuits to the client
  // To prevent issues where students see other peoples circuits, we will only do it on the server side for now...
  // This will at least check that the public inputs are what we expect
  useEffect(() => {
    // Only proceed if we have proof data
    if (proof !== '') {
      // Get selected users' public keys
      const publicKeys = users
        .filter((user) => selectedUserIds.includes(user._id))
        .map((user) => user.public_key || '')
        .filter((key) => key !== '') // Filter out empty keys
        .sort(); // Sort keys for consistent ordering

      // Verify the proof with the current message and public keys
      verifyProofInputs(proof, message, publicKeys).then(
        (_) => {
          setError(''); // Clear any previous errors if verification succeeds
          console.log('Proof is valid!');
        },
        (exception) => {
          setError(exception);
        },
      );
    }
  }, [message, selectedUserIds, proof, users]);

  const handleDownloadJson = async () => {
    // Get selected users' public keys
    const public_keys = users
      .filter((user) => selectedUserIds.includes(user._id))
      .map((user) => user.public_key || '')
      .filter((key) => key !== '') // Filter out empty keys
      .sort(); // Sort keys for consistent ordering

    console.log(selectedUserIds);
    console.log(
      'users: ',
      users.filter((user) => selectedUserIds.includes(user._id)),
    );

    // Create download data
    const downloadData = {
      public_keys,
      message: message.trim(),
    };

    // Create and trigger download
    const dataStr = JSON.stringify(downloadData, null, 2);
    try {
      // Check if the File System Access API is available
      if ('showSaveFilePicker' in window) {
        // Open a file save dialog
        const fileHandle = await window.showSaveFilePicker({
          suggestedName: 'public_input.json',
          types: [
            {
              description: 'JSON Files',
              accept: { 'application/json': ['.json'] },
            },
          ],
        });

        // Create a writable stream and write the data
        const writableStream = await fileHandle.createWritable();
        await writableStream.write(dataStr);
        await writableStream.close();
      } else {
        // Fallback for browsers that don't support the File System Access API
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.download = 'public_input.json';
        link.href = url;
        link.click();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Error saving file:', error);
    }
  };

  const handleProofFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setProofFileName(file.name);

    // Read and parse the JSON file
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const jsonData = JSON.parse(event.target?.result as string);

        // Validate the JSON structure
        if (!jsonData.proof || typeof jsonData.proof !== 'string') {
          setError('Invalid proof format: must contain "proof" as string');
          return;
        }

        // Store the proof data - verification will be handled by useEffect
        setProof(jsonData.proof);
        setError(''); // Clear any previous errors
      } catch (error) {
        setError('Invalid JSON file format');
      }
    };
    reader.readAsText(file);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (selectedUserIds.length === 0) {
      setError('Please select at least one author');
      return;
    }

    if (!message.trim()) {
      setError('Please enter a message');
      return;
    }

    if (selectedUserIds.length > 32) {
      setError('Cannot select more than 32 authors');
    }

    if (selectedCircuit === null) {
      setError('Please select your circuit');
      return;
    }

    console.log(proof);
    if (proof.length === 0) {
      setError('Please upload a valid proof file');
      return;
    }
    console.log(selectedCircuit);

    onAddPost({
      userIds: selectedUserIds,
      message,
      proof,
      circuit_id: selectedCircuit,
    });

    // Reset form
    setMessage('');
    setError('');
    setProofFileName('');
    setProof('');
    setSelectedUserIds([]);
  };

  const handleUserSelect = (userId: number) => {
    setSelectedUserIds((prev) => {
      // If user is already selected, remove them
      if (prev.includes(userId)) {
        return prev.filter((id) => id !== userId);
      }
      // Otherwise add them to selection
      return [...prev, userId];
    });
  };

  return (
    <Card>
      <CardContent className="pt-6">
        <h2 className="text-xl font-semibold mb-4">Post a Message</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="user" className="block text-sm font-medium mb-1">
              Post as
            </label>
            <MultiSelect
              onValueChange={(values: string[]) => {
                // For each user ID in values that's not in selectedUserIds, call onSelectUser
                values.forEach((userId: string) => {
                  let userIdNum = Number(userId);
                  if (!selectedUserIds.includes(userIdNum)) {
                    handleUserSelect(userIdNum);
                  }
                });

                // For each user ID in selectedUserIds that's not in values, call onSelectUser to toggle it off
                selectedUserIds.forEach((userId) => {
                  if (!values.includes(String(userId))) {
                    handleUserSelect(userId);
                  }
                });
              }}
            >
              <MultiSelectTrigger id="user" className="w-full">
                <MultiSelectValue placeholder="Select users" />
              </MultiSelectTrigger>
              <MultiSelectContent
                searchPlaceholder="Search users..."
                onSearch={(query: string, items: any[]) => {
                  if (!query.trim()) return items;

                  return items.filter((item: any) => {
                    // Extract the user name from the item component
                    const userName =
                      users.find((user) => user._id === item.props.value)?.name || '';
                    return userName.toLowerCase().includes(query.toLowerCase());
                  });
                }}
              >
                {users.map((user) => (
                  <MultiSelectItem key={user._id} value={String(user._id)}>
                    <div className="flex items-center gap-2">
                      <Avatar className="h-6 w-6">
                        <AvatarImage src={user.avatar} alt={user.name} />
                        <AvatarFallback>
                          {user.name
                            .split(' ')
                            .map((n) => n[0])
                            .join('')
                            .toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                      <span className="text-primary">{user.name}</span>
                    </div>
                  </MultiSelectItem>
                ))}
              </MultiSelectContent>
            </MultiSelect>
          </div>
          <div>
            <label htmlFor="message" className="block text-sm font-medium mb-1">
              Message
            </label>
            <Textarea
              id="message"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="What's on your mind?"
              className="w-full min-h-[100px]"
            />
            <div className="flex justify-between mt-1">
              <div className="mt-1">
                <button
                  type="button"
                  onClick={handleDownloadJson}
                  className="text-sm text-blue-600 hover:text-blue-800 hover:underline"
                >
                  Download proof input
                </button>
              </div>
            </div>
          </div>

          <div>
            <label htmlFor="circuit" className="block text-sm font-medium mb-1">
              Circuit
            </label>
            <Select onValueChange={(value) => setSelectedCircuit(Number(value))}>
              <SelectTrigger id="selected_circuit" className="w-full">
                <SelectValue
                //placeholder={<span className="text-muted-foreground">Select a circuit</span>}
                >
                  {selectedCircuit ? (
                    circuits.find((circuit) => circuit._id === selectedCircuit)?.name
                  ) : (
                    <span className="text-muted-foreground">Select a circuit</span>
                  )}
                </SelectValue>
              </SelectTrigger>
              <SelectContent
                searchable={true}
                searchPlaceholder="Search circuits..."
                onSearch={(query: string, items: any[]) => {
                  if (!query.trim()) return items;

                  return items.filter((item: any) => {
                    const circuitName =
                      circuits.find((circuit) => circuit._id === item.props.value)?.name || '';
                    return circuitName.toLowerCase().includes(query.toLowerCase());
                  });
                }}
              >
                {circuits
                  .slice() // Create a shallow copy to avoid mutating the original array
                  .sort((a, b) => a.name.localeCompare(b.name)) // Sort users alphabetically by name
                  .map((circuit) => (
                    <SelectItem key={circuit._id} value={String(circuit._id)}>
                      <div className="flex items-center gap-2">
                        <span className="text-primary">{circuit.name}</span>
                      </div>
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <label htmlFor="proof" className="block text-sm font-medium mb-1">
              Ring Signature Proof
            </label>
            <div className="flex items-center gap-2">
              <input
                id="proof"
                type="file"
                accept="application/json"
                className="hidden"
                onChange={handleProofFileChange}
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => document.getElementById('proof')?.click()}
              >
                Choose JSON File
              </Button>
              {proofFileName ? (
                <div className="flex items-center w-full justify-between">
                  <span className="text-sm text-muted-foreground truncate max-w-[200px]">
                    {proofFileName}
                  </span>
                </div>
              ) : (
                <span className="text-sm text-muted-foreground">No file selected</span>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Upload a JSON file generated from your circuit!
            </p>
          </div>

          {error && <p className="text-red-500 text-sm">{error}</p>}

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {selectedUsers.length > 0 ? (
                <span className="text-sm text-muted-foreground">
                  Posting as one of {selectedUsers.length}{' '}
                  {selectedUsers.length === 1 ? 'author' : 'authors'}
                </span>
              ) : (
                <span className="text-sm text-muted-foreground">No authors selected</span>
              )}
            </div>
            <Button type="submit">Post Message</Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
};

export default PostForm;
