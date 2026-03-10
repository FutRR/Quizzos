"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { login } from "../services/api";
import LoginForm from "../components/Login/LoginForm";

export default function LoginPage() {
    return <LoginForm />;
}