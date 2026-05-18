"""Multiplayer lobby — broker for invite-code matchmaking between friends.

Runs as a standalone FastAPI service (no dependency on the main Postgres /
Redis stack) so any friend in the group can host the lobby on their VPS.
SQLite is the persistence layer — players, invites, matches.
"""
