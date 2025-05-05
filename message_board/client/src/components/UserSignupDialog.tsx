import { useState } from 'react';
import { User } from '../types';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { z } from 'zod';

// Form validation schema
const userSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(50),
});

interface UserSignupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAddUser: (user: Omit<User, '_id'>) => void;
}

const UserSignupDialog = ({ open, onOpenChange, onAddUser }: UserSignupDialogProps) => {
  const [name, setName] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [publicKeyFileName, setPublicKeyFileName] = useState<string>('');
  const [publicKey, setPublicKey] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const resetForm = () => {
    setName('');
    setErrors({});
  };

  const handleClose = () => {
    resetForm();
    onOpenChange(false);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    let newErrors = { ...errors };
    delete newErrors.name;

    try {
      // Validate form data
      userSchema.parse({ name });

      if (errors.public_key) {
        setIsSubmitting(false);
        return;
      }

      // Add the new user
      onAddUser({ name, avatar: '', public_key: publicKey });

      // Close the dialog and reset form
      handleClose();
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Convert Zod errors to a more usable format
        const formattedErrors: Record<string, string> = {};
        error.errors.forEach((err) => {
          if (err.path) {
            formattedErrors[err.path[0]] = err.message;
          }
        });
        if (newErrors.public_key) {
          formattedErrors.public_key = newErrors.public_key;
        }
        setErrors(formattedErrors);
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handlePublicKeyFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setPublicKeyFileName(file.name);
    let newErrors = { ...errors };
    delete newErrors.public_key;

    // Read and parse the JSON file
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const jsonData = JSON.parse(event.target?.result as string);

        // Validate the JSON structure
        if (!jsonData.public_key || typeof jsonData.public_key !== 'string') {
          setErrors({
            ...newErrors,
            public_key: 'Invalid public key format: must contain "public_key" as string',
          });
          return;
        }

        setPublicKey(jsonData.public_key);
        setErrors({ ...newErrors });
      } catch (error) {
        setErrors({ ...newErrors, public_key: 'Invalid JSON file format' });
      }
    };
    reader.readAsText(file);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Create New User</DialogTitle>
          <DialogDescription>
            Fill out the form below to create a new user profile.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="name">Full Name</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter your full name"
            />
            {errors.name && <p className="text-red-500 text-xs">{errors.name}</p>}
          </div>

          <div className="space-y-2">
            <label htmlFor="public_key" className="block text-sm font-medium">
              RSA Public Key (e.g. "keypair.json.pub")
            </label>
            <div className="flex items-center gap-2">
              <input
                id="public_key"
                type="file"
                accept="application/json"
                className="hidden"
                onChange={handlePublicKeyFileChange}
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => document.getElementById('public_key')?.click()}
              >
                Choose JSON File
              </Button>
              {publicKeyFileName ? (
                <div className="flex items-center w-full justify-between">
                  <span className="text-sm text-muted-foreground truncate max-w-[200px]">
                    {publicKeyFileName}
                  </span>
                </div>
              ) : (
                <span className="text-sm text-muted-foreground">No file selected</span>
              )}
            </div>
            <div>
              {errors.public_key && <p className="text-red-500 text-xs">{errors.public_key}</p>}
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? 'Creating...' : 'Create User'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default UserSignupDialog;
