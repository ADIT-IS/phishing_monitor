from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from ai_model import analyze_url

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Mount templates/static
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Request model
class URLRequest(BaseModel):
    url: str

@app.post("/check")
async def check_url(payload: URLRequest):
    score, verdict = analyze_url(payload.url)
    return JSONResponse({"score": score, "verdict": verdict})
