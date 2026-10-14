// SPDX-FileCopyrightText: 2021-2025 DINUM <floss@numerique.gouv.fr>
// SPDX-FileCopyrightText: 2024-2025 Université Grenoble Alpes
// SPDX-License-Identifier: MIT

import { Kysely } from "kysely";
import { beforeAll, describe, expect, it } from "vitest";
import { Database } from "../core/adapters/dbApi/kysely/kysely.database";
import { resetDB } from "../tools/test.helpers";
import { ApiCaller, createTestCaller, defaultUser } from "./createTestCaller";

/*
 * Security PoC — IDOR on the getUser (by email) tRPC query.
 *
 * Agent A unchecked "Profil Public" in "Mon compte" (isPublic: false).
 * Agent B is ANY other standard authenticated agent (role: "user"), with no
 * relation to A. B calls getUser({ email: A.email }).
 *
 * Expected behavior: the API must refuse with UNAUTHORIZED (the
 * `!currentUser && !user.isPublic` guard in makeGetUser was designed to protect
 * private profiles). Because getUser is a protectedProcedure, `currentUser` is
 * always defined when reached through the router, so the guard is dead code and
 * B receives A's full private profile (email, organization, about, sub, role).
 */

const privateUserA = {
    email: "userA@mail.com",
    organization: "Ministère Exemple",
    about: "à propos privé de A",
    sub: "user-a-sub"
};

const attackerUserB: typeof defaultUser = {
    ...defaultUser,
    id: 7,
    sub: "user-b-sub",
    email: "userB@mail.com",
    organization: "Autre organisation",
    role: "user"
};

describe("getUser (by email) — private profile access control", () => {
    let apiCaller: ApiCaller;
    let kyselyDb: Kysely<Database>;

    beforeAll(async () => {
        // Get a db handle without creating any user nor session.
        ({ kyselyDb } = await createTestCaller({ currentUser: undefined }));
        await resetDB(kyselyDb);

        // Agent A exists in db with a PRIVATE profile, as if A had unchecked
        // "Profil Public" from the account page. Inserted directly (same
        // pattern as insertSoftwareRow in routes.e2e.test.ts) because a second
        // createTestCaller({ currentUser }) on the same db would collide on the
        // fixed user_sessions.id UUID.
        await kyselyDb
            .insertInto("users")
            .values({
                id: 42,
                email: privateUserA.email,
                organization: privateUserA.organization,
                about: privateUserA.about,
                isPublic: false,
                sub: privateUserA.sub,
                role: "user",
                createdAt: new Date(),
                updatedAt: new Date()
            })
            .execute();

        // Agent B: a standard authenticated agent, unrelated to A.
        ({ apiCaller, kyselyDb } = await createTestCaller({ db: kyselyDb, currentUser: attackerUserB }));
    });

    it("leaks the full private profile of agent A to any other authenticated agent (demonstrates the vulnerability)", async () => {
        const { user } = await apiCaller.getUser({ email: privateUserA.email });

        // This assertion PASSES precisely because the private data is disclosed.
        expect(user).toMatchObject({
            id: 42,
            email: "userA@mail.com",
            isPublic: false,
            organization: "Ministère Exemple",
            about: "à propos privé de A",
            sub: "user-a-sub",
            role: "user"
        });
    });

    it("must refuse with UNAUTHORIZED when another authenticated agent reads a private profile (security regression test)", async () => {
        await expect(apiCaller.getUser({ email: privateUserA.email })).rejects.toThrow("UNAUTHORIZED");
    });
});
