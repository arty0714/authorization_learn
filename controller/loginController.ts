import { type Request, type Response } from "express";
import { checkPassword, hashPassword } from "../service/loginService.ts";
import { ValidationError } from "../index.ts";
//variables
type User = {
  username: string,
  hash: string
}
let users: User[] = [];


export async function signInController(req: Request, res: Response) {
  const { username, password }: { username: string, password: string} = req.body;

  const userFound = users.find(user => user.username == username);
  if (!userFound) throw new ValidationError("User not found")
  
  const passwordValid = await checkPassword(password, userFound.hash)
  if (!passwordValid) throw new ValidationError("Password isn\'t valid")
  
  res.send('sign-in')
}
export async function signUpController(req: Request, res: Response) {
  const { username, password } = req.body;

  const hash = await hashPassword(password);

  users.push({username, hash});

  res.send('sign-up')
}