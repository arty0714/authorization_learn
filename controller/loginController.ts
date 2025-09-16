import { type Request, type Response } from "express";
import { checkPassword, hashPassword } from "../service/loginService.ts";
import { AppError, ValidationError } from "../index.ts";
import { v4 as uuidv4 } from 'uuid';
import jwt from "jsonwebtoken";

//variables
import { users, createSession, sessionExists } from "../db/index.ts";

const jwtSecret = process.env.JWTSECRET;


export async function signInController(req: Request, res: Response) {
  const { username, password }: { username: string, password: string} = req.body;

  const userFound = users.find(user => user.username == username);
  if (!userFound) throw new ValidationError("User not found")
  
  const passwordValid = await checkPassword(password, userFound.hash)
  if (!passwordValid) throw new ValidationError("Password isn\'t valid")
  
  const accessToken = jwt.sign({ id: userFound.id }, jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '1m'
  })
  const refreshToken = jwt.sign({ id: userFound. id }, jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '7d'
  })

  createSession(refreshToken);
  
  res.cookie("refreshToken", refreshToken, {
    maxAge: 1000 * 60 * 60 * 24 * 7,
    httpOnly: true,
    path: '/user/refresh',
    sameSite: 'strict'
  })


  res.json({
    message: "success",
    data: accessToken
  })
}
export async function signUpController(req: Request, res: Response) {
  const { username, password } = req.body;

  const hash = await hashPassword(password);

  users.push({username, hash, id: uuidv4(), twofaEnabled: false});

  res.json({
    message: "Registration complete. Please sign in"
  })
}
export async function refreshAccessToken(req: Request, res: Response) {
  const refreshToken: string = req.cookies.refreshToken;

  if (!refreshToken) throw new AppError("no refresh token", 500);
  if (!sessionExists(refreshToken)) throw new ValidationError("refresh token is not valid");

  const payload = jwt.verify(refreshToken, jwtSecret);
  const userId = payload.id;
  const accessToken = jwt.sign({ id: userId }, jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '1m'
  })

  res.status(200).json({
    message: 'success',
    data: accessToken
  })
}

export async function logout(req:Request, res: Response) {
  
}