using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MonAPIDotNet.Migrations
{
    /// <inheritdoc />
    public partial class UpdateImpostorGameEntities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "EliminatedAt",
                table: "ImpostorPlayers",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "HasVoted",
                table: "ImpostorPlayers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "VotedForPlayerId",
                table: "ImpostorPlayers",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Winner",
                table: "ImpostorGameSessions",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EliminatedAt",
                table: "ImpostorPlayers");

            migrationBuilder.DropColumn(
                name: "HasVoted",
                table: "ImpostorPlayers");

            migrationBuilder.DropColumn(
                name: "VotedForPlayerId",
                table: "ImpostorPlayers");

            migrationBuilder.DropColumn(
                name: "Winner",
                table: "ImpostorGameSessions");
        }
    }
}
