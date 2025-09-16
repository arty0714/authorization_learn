import { sensitiveHeaders } from "http2";
import { ref } from "process";

type User = {
  id: string,
  username: string,
  hash: string,
  twofaEnabled: boolean,
}

export let users: User[] = [];
export let sessions: string[] = [];

export function createSession(refreshToken: string): void {
  sessions.push(refreshToken);
}

export function revokeSession(refreshToken: string): void {
  sessions = sessions.filter(token => token != refreshToken);
}

export function sessionExists(refreshToken: string): boolean {
  return sessions.includes(refreshToken);
}
export function enabletwofa(userId: string): void {
  const userFound = users.find(user => user.id == userId);

  if (!userFound) throw Error("user not found");

  userFound.twofaEnabled = true;
}

export function disabletwofa(userId: string): void {
  const userFound = users.find(user => user.id == userId);

  if (!userFound) throw Error("user not found");

  userFound.twofaEnabled = false;
}