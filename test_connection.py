import asyncio
from azure.identity import InteractiveBrowserCredential
from msgraph import GraphServiceClient

async def test_connection():
    print("🔐 Testing Microsoft Graph connection...")
    
    # Create credential with specific scopes
    scopes = [
        "User.Read",           # Read your own profile
        "User.Read.All",       # Read all users
        "Group.Read.All",      # Read all groups
        "Directory.Read.All",  # Read directory data
    ]
    
    credential = InteractiveBrowserCredential(
        client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Explorer client ID
    )
    
    # Create Graph client with scopes
    client = GraphServiceClient(credentials=credential, scopes=scopes)
    
    print("✅ Authentication successful!")
    print("Testing API call...")
    
    try:
        # Test: Get all users (just count them)
        users = await client.users.get()
        user_count = len(users.value) if users.value else 0
        print(f"✅ Successfully read directory data!")
        print(f"   Found {user_count} users in tenant")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure you're signing in with an admin account")
        print("2. You may need to consent to permissions")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_connection())
    if success:
        print("\n🎉 Ready to build the scanner!")
    else:
        print("\n⚠️  Fix permissions before continuing")
