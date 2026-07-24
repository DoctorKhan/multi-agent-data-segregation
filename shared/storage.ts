export class InMemoryStore {
  private data = new Map<string, string>();

  private storageKey(owner: string, key: string): string {
    return `${owner.toLowerCase()}\0${key}`;
  }

  write(owner: string, key: string, value: string): void {
    this.data.set(this.storageKey(owner, key), value);
  }

  read(owner: string, key: string): string | null {
    return this.data.get(this.storageKey(owner, key)) ?? null;
  }
}
