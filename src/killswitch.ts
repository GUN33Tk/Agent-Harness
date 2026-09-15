import * as fs from "fs";

export class KillSwitch {
  constructor(private flagPath: string) {}

  isSet(): boolean {
    return fs.existsSync(this.flagPath); // lives on disk, outside the model's own context
  }

  trigger(): void {
    fs.writeFileSync(this.flagPath, "halted");
  }

  reset(): void {
    if (fs.existsSync(this.flagPath)) fs.unlinkSync(this.flagPath);
  }
}
