import express, { type ErrorRequestHandler, type NextFunction, type Request, type Response } from "express";
import cors from "cors"
import cookieParser from 'cookie-parser';
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";


import { refreshAccessToken, signInController, signUpController } from "./controller/loginController.ts";
import { generate2fa, validate2fa } from "./controller/2faController.ts";
import { users } from "./db/index.ts"

export class AppError extends Error {
  status: number;

  constructor(message, status) {
    super(message)
    this.status = status;
  }
}

export class ValidationError extends AppError {
  details: string[];

  constructor(message, details=[]) {
    super(message, 400);
    this.details = details;
  }
}


const app = express();

app.use(cors())
app.use(bodyParser.json())
app.use(cookieParser())

app.post("/user/sign-in", validateUserBody, signInController)
app.post("/user/sign-up", validateUserBody, signUpController)
app.post("/user/2fa/generate", generate2fa)
app.post("/user/2fa/validate", validate2fa)
app.post("/user/refresh", refreshAccessToken)

// app.post("/")

app.get('/', validateAuth, (req: Request, res: Response) => {
  res.status(200).json({ user: req.user})
})

//error handler
app.use(errorHandler);


app.listen(process.env.PORT, () => {
  console.log("server");
})

//middleware
function validateUserBody(req: Request, res: Response, next: NextFunction) {
  const valdationErrorMessage = "no username or password";
  const noBodyMessage = "no body"
  
  if(!req.body) throw new ValidationError('no body')
  if(!req.body.username) throw new ValidationError('no username')
  if(!req.body.password) throw new ValidationError('no password')
  
  next()
}

function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
  console.error("Error: ", err.message)

  res.status(err.status || 500).json({
    status: "Error",
    message: err.message || "Internal server error",
    details: err.details || []
  })
}

async function validateAuth(req: Request, res: Response, next: NextFunction) {
  const jwtTokenHeader: string = process.env.JWTHEADER || '';
  const jwtSecret: string = process.env.JWTSECRET || '';
  
  // check if there is a token
  const token = req.header(jwtTokenHeader);

  if (!token) throw new ValidationError('no token');

  // check if token is valid
  const tokenData = jwt.verify(token, jwtSecret);

  if (!tokenData) throw new ValidationError('token isnt valid');

  //check if user exist
  const userFound = users.find(user => user.id == tokenData.id);
  if (!userFound) throw new ValidationError('user doesnt exist');

  //check if user has enabled 2fa and if there is a 2fa property in token
  if (userFound.twofaEnabled && !tokenData.twofaAuthorized) throw new ValidationError('2fa missing');
  
  //@ts-ignore
  req.user = { username: userFound.username, twofaEnabled: userFound.twofaEnabled }

  next();
}