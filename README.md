# SENTINEL

Security Tools Subscription Platform.

## Project asset import

`POST /api/projects/import` (authenticated) accepts a multipart upload with an
`archive` field containing a `.zip` of project assets and a `projectId` field.
The archive is extracted into `uploads/<projectId>/`, preserving the folder
structure from the zip. Responds with the list of extracted file paths.
