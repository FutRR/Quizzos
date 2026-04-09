using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MonAPIDotNet.Migrations
{
    /// <inheritdoc />
    public partial class SeedAuthorizedApp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AuthorizedApplications",
                columns: new[] { "Id", "Audience" },
                values: new object[] { 1, "API_App" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AuthorizedApplications",
                keyColumn: "Id",
                keyValue: 1);
        }
    }
}
