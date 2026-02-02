## Simple PowerShell Web Server for SecureHub
## This creates a local web server on port 8000

$port = 8000
$directory = Get-Location

Write-Host "Starting web server on http://localhost:$port" -ForegroundColor Green
Write-Host "Serving files from: $directory" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Create HTTP listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()

Write-Host "Server is running! Opening browser..." -ForegroundColor Green
Start-Process "http://localhost:$port/unified-index.html"

try {
    while ($listener.IsListening) {
        # Wait for a request
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        # Get the requested file path
        $path = $request.Url.LocalPath
        if ($path -eq "/") {
            $path = "/unified-index.html"
        }
        $filePath = Join-Path $directory $path.TrimStart('/')

        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Request: $path" -ForegroundColor Gray

        # Check if file exists
        if (Test-Path $filePath -PathType Leaf) {
            # Read file content
            $content = [System.IO.File]::ReadAllBytes($filePath)
            
            # Set content type based on file extension
            $extension = [System.IO.Path]::GetExtension($filePath)
            $contentType = switch ($extension) {
                ".html" { "text/html" }
                ".css"  { "text/css" }
                ".js"   { "application/javascript" }
                ".json" { "application/json" }
                ".png"  { "image/png" }
                ".jpg"  { "image/jpeg" }
                ".gif"  { "image/gif" }
                ".svg"  { "image/svg+xml" }
                default { "application/octet-stream" }
            }
            
            $response.ContentType = $contentType
            $response.ContentLength64 = $content.Length
            $response.StatusCode = 200
            $response.OutputStream.Write($content, 0, $content.Length)
        }
        else {
            # File not found
            $response.StatusCode = 404
            $responseString = "<html><body><h1>404 - File Not Found</h1><p>$path</p></body></html>"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseString)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            Write-Host "  -> 404 Not Found" -ForegroundColor Red
        }
        
        $response.Close()
    }
}
finally {
    $listener.Stop()
    Write-Host "`nServer stopped." -ForegroundColor Yellow
}
