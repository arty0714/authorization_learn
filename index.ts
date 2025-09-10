import express, { type ErrorRequestHandler, type NextFunction, type Request, type Response } from "express";
import cors from "cors"
import bodyParser from "body-parser";

import { signInController, signUpController } from "./controller/loginController.ts";


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

app.use('/user', validateUserBody)
app.post("/user/sign-in", signInController)
app.post("/user/sign-up", signUpController)

app.get('/', (req: Request, res: Response) => {
  res.send('dont get from here')
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