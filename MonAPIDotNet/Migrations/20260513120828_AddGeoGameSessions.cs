using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MonAPIDotNet.Migrations
{
    /// <inheritdoc />
    public partial class AddGeoGameSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "GeoGameSessions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<int>(type: "int", nullable: false),
                    StartedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    FinishedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    TotalScore = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GeoGameSessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "GeoGameRounds",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    SessionId = table.Column<int>(type: "int", nullable: false),
                    Index = table.Column<int>(type: "int", nullable: false),
                    ImageId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ActualLat = table.Column<double>(type: "float", nullable: false),
                    ActualLng = table.Column<double>(type: "float", nullable: false),
                    GuessLat = table.Column<double>(type: "float", nullable: true),
                    GuessLng = table.Column<double>(type: "float", nullable: true),
                    DistanceKm = table.Column<double>(type: "float", nullable: true),
                    Score = table.Column<int>(type: "int", nullable: true),
                    GeoGameSessionId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GeoGameRounds", x => x.Id);
                    table.ForeignKey(
                        name: "FK_GeoGameRounds_GeoGameSessions_GeoGameSessionId",
                        column: x => x.GeoGameSessionId,
                        principalTable: "GeoGameSessions",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_GeoGameRounds_GeoGameSessionId",
                table: "GeoGameRounds",
                column: "GeoGameSessionId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "GeoGameRounds");

            migrationBuilder.DropTable(
                name: "GeoGameSessions");
        }
    }
}
