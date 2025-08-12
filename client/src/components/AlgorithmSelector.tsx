import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { type EncryptionAlgorithm } from "@shared/schema";

interface AlgorithmSelectorProps {
  algorithms: EncryptionAlgorithm[];
  selectedAlgorithm: string;
  onAlgorithmChange: (algorithmId: string) => void;
}

export default function AlgorithmSelector({ 
  algorithms, 
  selectedAlgorithm, 
  onAlgorithmChange 
}: AlgorithmSelectorProps) {
  return (
    <div>
      <label className="block text-foreground font-medium mb-4">Encryption Algorithm</label>
      <RadioGroup value={selectedAlgorithm} onValueChange={onAlgorithmChange}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {algorithms.map((algorithm) => (
            <div key={algorithm.id}>
              <RadioGroupItem 
                value={algorithm.id} 
                id={algorithm.id} 
                className="sr-only peer" 
              />
              <Label 
                htmlFor={algorithm.id}
                className="cursor-pointer"
                data-testid={`algorithm-${algorithm.name}`}
              >
                <Card className="bg-card border-border peer-checked:border-primary peer-checked:bg-secondary hover:bg-secondary transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="text-foreground font-medium">{algorithm.displayName}</h4>
                        <p className="text-muted-foreground text-sm">{algorithm.description}</p>
                      </div>
                      <div className="flex flex-col items-end space-y-1">
                        {algorithm.isQuantumSafe && (
                          <Badge className="bg-green-500 bg-opacity-20 text-green-500 text-xs">
                            Quantum Safe
                          </Badge>
                        )}
                        {algorithm.isPostQuantum && (
                          <Badge className="bg-blue-500 bg-opacity-20 text-blue-500 text-xs">
                            Post-Quantum
                          </Badge>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </Label>
            </div>
          ))}
        </div>
      </RadioGroup>
    </div>
  );
}
