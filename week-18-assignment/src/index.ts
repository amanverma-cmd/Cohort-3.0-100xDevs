import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import z from "zod";
import "dotenv/config";
import { type Request, type Response } from "express";
import middleware from "./middleware.js";
import prisma from "./lib/db.js";


const app = express();
app.use(express.json());

app.post("/signup", async (req: Request, res: Response) => {
  const requiredBody = z.object({
    firstName: z.string().min(3).max(8),
    lastName: z.string().min(3).max(8),
    email: z.email(),
    password: z.string().min(8).max(8),
  });

  const parsedBody = requiredBody.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      message: "Invalid inputs",
    });
  }

  const { email, password, firstName, lastName } = parsedBody.data;

  const hashedPassword = await bcrypt.hash(password, 5);

  const userCreated = await prisma.user.create({
    data: {
      email: email,
      firstName: firstName,
      lastName: lastName,
      password: hashedPassword,
    },
  });

  if (userCreated) {
    return res.status(200).json({
      message: "User signed up successfully",
    });
  }
});

app.post("/signin", async (req: Request, res: Response) => {
  const requiredBody = z.object({
    email: z.email(),
    password: z.string().min(8).max(8),
  });

  const parsedBody = requiredBody.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      message: "Invalid inputs",
    });
  }

  const { email, password } = parsedBody.data;

  const userCreated = await prisma.user.findUnique({
    where: {
      email: email,
    },
  });

  if (!userCreated) {
    return res.status(400).json({
      message: "User not found!",
    });
  }

  const passwordMatch = await bcrypt.compare(password, userCreated.password);

  if (!passwordMatch) {
    return res.status(400).json({
      message: "Wrong Password",
    });
  }

  const id = userCreated.id;

  const token = jwt.sign(
    {
      email,
      id,
    },
    process.env.JWT_SECRET as string,
  );

  return res.status(200).json({
    token,
    message: "User successfully signed in",
  });
});

app.post("/todo/create", middleware, async (req: Request, res: Response) => {
  const userId = req.userId;
  const { title, description, isCompleted } = req.body;

  const createTodo = await prisma.todo.create({
    data: {
      title: title,
      description: description,
      isCompleted: isCompleted,
      userId: userId,
    },
  });

  if (createTodo) {
    return res.status(200).json({
      createTodo,
      message: "Todo successfully created",
    });
  }
});

app.patch(
  "/todo/update/:id",
  middleware,
  async (req: Request, res: Response) => {
    const todoId = Number(req.params.id);
    const userId = req.userId;

    const { title, description } = req.body;

    if (!todoId) {
      return res.status(400).json({
        message: "todo id is not given",
      });
    }

    const updateTodo = await prisma.todo.update({
      where: {
        userId: userId,
        id: todoId,
      },
      data: {
        title: title,
        description: description,
      },
    });

    if (updateTodo) {
      return res.status(200).json({
        updateTodo,
        message: "Todo updated successfully",
      });
    }
  },
);

app.delete(
  "/todo/delete/:id",
  middleware,
  async (req: Request, res: Response) => {
    const todoId = Number(req.params.id);
    const userId = req.userId;

    const deleteTodo = await prisma.todo.delete({
      where: {
        userId: userId,
        id: todoId,
      },
    });

    if (deleteTodo) {
      return res.status(200).json({
        message: "Todo deleted successfully",
      });
    }
});

app.get("/todos", middleware, async (req: Request, res: Response) => {
  const userId = req.userId;

  const todos = await prisma.todo.findMany({
    where: {
      userId: userId,
    },
  });

  if (todos) {
    return res.status(200).json({
      todos,
      message: "todos fetched successfully",
    });
  }
});

app.listen(3000, () => {
  console.log("server is running on port 3000");
});
