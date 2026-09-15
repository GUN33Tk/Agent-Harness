export class BudgetTracker {
  private spent = new Map<string, number>();
  constructor(private limits: Record<string, number>) {}

  spend(toolName: string): boolean {
    const used = (this.spent.get(toolName) ?? 0) + 1;
    this.spent.set(toolName, used);
    return used <= (this.limits[toolName] ?? Infinity);
  }

  usage(toolName: string): number {
    return this.spent.get(toolName) ?? 0;
  }
}
