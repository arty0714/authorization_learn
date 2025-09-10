import bcrypt from "bcrypt";

export async function hashPassword(password: string, saltRounds: number = 10): Promise<string> {
  const salt = await bcrypt.genSalt(saltRounds);
  const pepper = process.env.PEPPER;
  const hash = await bcrypt.hash(password + pepper, salt);

  return hash;
}
export async function checkPassword(password: string, hash: string): Promise<boolean> {
  const pepper = process.env.PEPPER;
  const passwordValid = await bcrypt.compare(password + pepper, hash);

  return passwordValid;
}