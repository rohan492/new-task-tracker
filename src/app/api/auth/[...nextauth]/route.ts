import NextAuth, { NextAuthOptions, User } from "next-auth";
import { Session, User as NextAuthUser } from "next-auth";
import { JWT } from "next-auth/jwt";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import LinkedInProvider from "next-auth/providers/linkedin";
import bcrypt from "bcrypt";
import prisma from "@/lib/db";


export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
    LinkedInProvider({
      clientId: process.env.LINKEDIN_CLIENT_ID!,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET!,
    }),
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const { email, password } = credentials!;
        const user = await prisma.user.findUnique({ where: { email } })

        if (!user || !user.password) {
          throw new Error("Invalid credentials");
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
          throw new Error("Invalid credentials");
        }

        return { id: user.id, name: user.name, email: user.email };
      },
    }),
  ],
  session: {
    strategy: "jwt" as const,
  },
  callbacks: {
    async jwt({ token, user }: { token: JWT, user: User }) {
      if (user) token.id = user.id;
      return token;
    },
    async session({ session, token }: { session: Session, token: JWT  }) {
      if (session.user && token) session.user.id = token.id as string;
      return session;
    },
  },
};

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
    } & NextAuthUser;
  }
}

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
