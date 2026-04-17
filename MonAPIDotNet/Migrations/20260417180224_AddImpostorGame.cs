using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MonAPIDotNet.Migrations
{
    /// <inheritdoc />
    public partial class AddImpostorGame : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ImpostorGameSessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Code = table.Column<string>(type: "nvarchar(6)", maxLength: 6, nullable: false),
                    Status = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    SecretWord = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ImpostorWord = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImpostorGameSessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ImpostorWordPairs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    WordA = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    WordB = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Category = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImpostorWordPairs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ImpostorPlayers",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    SessionId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Role = table.Column<int>(type: "int", nullable: false),
                    IsEliminated = table.Column<bool>(type: "bit", nullable: false),
                    JoinedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImpostorPlayers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ImpostorPlayers_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ImpostorPlayers_ImpostorGameSessions_SessionId",
                        column: x => x.SessionId,
                        principalTable: "ImpostorGameSessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ImpostorPlayers_SessionId",
                table: "ImpostorPlayers",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_ImpostorPlayers_UserId",
                table: "ImpostorPlayers",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ImpostorPlayers");

            migrationBuilder.DropTable(
                name: "ImpostorWordPairs");

            migrationBuilder.DropTable(
                name: "ImpostorGameSessions");
        }
    }
}
