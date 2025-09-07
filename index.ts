import express, { type NextFunction, type Request, type Response } from "express";
import cors from "cors"
import bodyParser from "body-parser";
import bcrypt from 'bcrypt';

//variables
type User = {
  username: string,
  hash: string
}
let users: User[] = [];


const app = express();

app.use(cors())
app.use(bodyParser.json())

app.use('/user', validateUserBody)
app.post("/user/sign-in", signInController)
app.post("/user/sign-up", signUpController)

app.get('/', (req: Request, res: Response) => {
  res.send('dont get from here')
})
app.listen(process.env.PORT, () => {
  console.log("server");
})

//middleware
function validateUserBody(req: Request, res: Response, next: NextFunction) {
  const valdationErrorMessage = "no username or password";
  const noBodyMessage = "no body"
  
  if(!req.body) return res.status(500).send(noBodyMessage)
  if(!req.body.username) return res.status(401).send(valdationErrorMessage)
  if(!req.body.password) return res.status(401).send(valdationErrorMessage)
  
  next()
}

//controllers
async function signInController(req: Request, res: Response) {
  const { username, password }: { username: string, password: string} = req.body;

  const userFound = users.find(user => user.username == username);
  if (!userFound) return res.status(401).send("user not found");
  
  const passwordValid = await checkPassword(password, userFound.hash)
  if (!passwordValid) return res.status(401).send("password isnt valid")
  
  res.send('sign-in')
}
async function signUpController(req: Request, res: Response) {
  const { username, password } = req.body;

  const hash = await hashPassword(password);

  users.push({username, hash});

  res.send('sign-up')
}

//services
async function hashPassword(password: string, saltRounds: number = 10): Promise<string> {
  const salt = await bcrypt.genSalt(saltRounds);
  const pepper = process.env.PEPPER;
  const hash = await bcrypt.hash(password + pepper, salt);

  return hash;
}
async function checkPassword(password: string, hash: string): Promise<boolean> {
  const pepper = process.env.PEPPER;
  const passwordValid = await bcrypt.compare(password + pepper, hash);

  return passwordValid;
}