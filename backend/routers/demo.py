from fastapi import APIRouter, HTTPException
from scripts.seed_demo_data import seed_data

router = APIRouter(tags=['demo'])

@router.get('/demo/seed')
def run_seed():
    try:
        seed_data()
        return {"seeded": True, "counts": {"sessions": 5, "analyses": 3, "alerts": 10}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to seed demo data: {str(e)}")
