"""Template plugin for AI-Contained."""

from typing import cast

from fastmcp import Context, FastMCP


async def register(mcp: FastMCP) -> None:
    """Register tools, resources and prompts with the MCP server."""
    scenes = {
        "forest": "🌲 You're in a dark forest. Paths lead left and right.",
        "cave": "🕯 You enter a cave. It's dark. A glowing chest sits in the corner.",
        "river": "🌊 You reach a river. A small boat is tied to the bank.",
        "win": "🏆 You found the treasure! You win!",
        "lose": "💀 You slipped and fell into the river. Game over!",
    }

    transitions = {
        "forest": {"go left": "cave", "go right": "river"},
        "cave": {"open chest": "win", "go back": "forest"},
        "river": {"take boat": "win", "jump across": "lose", "go back": "forest"},
    }

    # --- Tool ---

    @mcp.tool()
    async def play_adventure(ctx: Context) -> str:
        """Play a short choose-your-own-adventure game."""
        scene = "forest"

        while scene not in ("win", "lose"):
            choices = list(transitions[scene].keys())
            result = await ctx.elicit(message=scenes[scene], response_type=choices)  # type: ignore[arg-type]  # https://github.com/python/mypy/issues/11613

            if result.action != "accept":
                return "Adventure abandoned."

            scene = transitions[scene][cast(str, result.data)]

        stats = await ctx.get_state("stats") or {"health": 100, "adventures": 0}

        if scene == "win":
            stats["health"] = min(100, stats["health"] + 10)
        else:
            stats["health"] = max(0, stats["health"] - 10)

        stats["adventures"] += 1
        await ctx.set_state("stats", stats)

        return f"{scenes[scene]} Current stats: adventure://stats"

    # --- Resource ---

    @mcp.resource("adventure://stats", mime_type="application/json")
    async def adventure_stats(ctx: Context) -> dict[str, int]:
        """Return current player stats."""
        return await ctx.get_state("stats") or {"health": 100, "adventures": 0}

    # --- Prompt ---
    # NOTE: Prompts don't appear to be supported/discoverable in claude-cli.
    # The prompt is registered and accessible via the MCP protocol directly.

    @mcp.prompt()
    async def adventure_recap() -> str:
        """Generate a recap based on the player's stats."""
        return (
            "Read adventure://stats then write a short dramatic recap of the player's journey. "
            "If health is 0, make it a tale of defeat. If 100, a tale of triumph."
        )
