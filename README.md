# Moodle MCP Server

A Model Context Protocol server that provides read-only access to courses on any
Moodle site. This server enables LLMs to list courses, files and assignments and
to read course files.

## Available Tools

- `list_courses` - Lists the courses the user is enrolled in.
- `list_course_files` - Lists the files of one course.
- `list_assignments` - Lists assignments with their deadlines.
- `read_course_file` - Reads a course file as text or as page images.

## Usage

Add the server as a custom connector in an MCP client:

`https://moodle.mcp.zahraabouzeid.me/mcp`

The sign-in page asks for the Moodle address and then opens the Moodle sign-in. The sign-in requires a browser on a computer.

## Security

This server stores the login encrypted on the server. A connection unused for 90
days is deleted. Only connect an account if you trust the operator of this server.

## License

This project is licensed under the [AGPL-3.0](LICENSE).
