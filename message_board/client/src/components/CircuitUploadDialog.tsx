import { useState } from 'react';
import { Circuit } from '../types';
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

interface CircuitUploadDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAddCircuit: (user: Omit<Circuit, '_id'>) => void;
}

const CircuitUploadDialog = ({ open, onOpenChange, onAddCircuit }: CircuitUploadDialogProps) => {
  const [name, setName] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [circuitFileName, setCircuitFileName] = useState<string>('');
  const [circuit, setCircuit] = useState<{
    verifier_circuit_data: string;
    circuit: string;
  } | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const resetForm = () => {
    setName('');
    setErrors({});
  };

  const handleClose = () => {
    resetForm();
    onOpenChange(false);
  };

  console.log(errors);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    let newErrors = { ...errors };
    delete newErrors.name;

    if (name.length < 2) {
      setErrors({ ...newErrors, name: 'Name must be at least 2 characters' });
      setIsSubmitting(false);
      return;
    }

    if (errors.circuit) {
      setIsSubmitting(false);
      return;
    }

    // Add the new user
    onAddCircuit({
      name,
      circuit: circuit?.circuit || '',
      verifier_circuit_data: circuit?.verifier_circuit_data || '',
    });

    // Close the dialog and reset form
    handleClose();
    setIsSubmitting(false);
  };

  const handleCircuitFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    let newErrors = { ...errors };
    delete newErrors.circuit;
    console.log('new errors:', newErrors);

    setCircuitFileName(file.name);

    // Read and parse the JSON file
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const jsonData = JSON.parse(event.target?.result as string);
        console.log('Parsed JSON data:', jsonData);

        console.log('Circuit data:', !jsonData.circuit || typeof jsonData.circuit !== 'string');
        // Validate the JSON structure
        if (!jsonData.circuit || typeof jsonData.circuit !== 'string') {
          setErrors({ ...newErrors, circuit: 'Invalid circuit: must contain "circuit" as string' });
          return;
        }

        if (!jsonData.verifier_circuit_data || typeof jsonData.verifier_circuit_data !== 'string') {
          setErrors({
            ...newErrors,
            circuit: 'Invalid circuit: must contain "verifier_circuit_data" as string',
          });
          return;
        }

        setCircuit({
          circuit: jsonData.circuit,
          verifier_circuit_data: jsonData.verifier_circuit_data,
        });
        setErrors(newErrors);
      } catch (error) {
        setErrors({ ...newErrors, circuit: 'Invalid JSON file format' });
      }
    };
    reader.readAsText(file);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Upload a new circuit</DialogTitle>
          <DialogDescription>
            Fill out the form below to upload a new ring signature circuit.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="name">Circuit Name</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter a name for the circuit"
            />
            {errors.name && <p className="text-red-500 text-xs">{errors.name}</p>}
          </div>

          <div className="space-y-2">
            <label htmlFor="circuit" className="block text-sm font-medium">
              Verifier Circuit (e.g. "circuit_verifier.json")
            </label>
            <div className="flex items-center gap-2">
              <input
                id="circuit"
                type="file"
                accept="application/json"
                className="hidden"
                onChange={handleCircuitFileChange}
              />
              <Button
                type="button"
                variant="outline"
                onClick={() => document.getElementById('circuit')?.click()}
              >
                Choose JSON File
              </Button>
              {circuitFileName ? (
                <div className="flex items-center w-full justify-between">
                  <span className="text-sm text-muted-foreground truncate max-w-[200px]">
                    {circuitFileName}
                  </span>
                </div>
              ) : (
                <span className="text-sm text-muted-foreground">No file selected</span>
              )}
            </div>
            <div>{errors.circuit && <p className="text-red-500 text-xs">{errors.circuit}</p>}</div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? 'Uploading...' : 'Upload Circuit'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default CircuitUploadDialog;
