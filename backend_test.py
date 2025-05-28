import requests
import sys
import uuid
from datetime import datetime

class WeatherAlertAPITester:
    def __init__(self, base_url="https://d68ce693-8ac4-4daa-b6fd-2db6cb991535.preview.emergentagent.com"):
        self.base_url = base_url
        self.user_token = None
        self.admin_token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_username = f"test_user_{datetime.now().strftime('%H%M%S')}"
        self.test_password = "TestPass123!"
        self.admin_username = "adminusernamealert"
        self.admin_password = "adminpasswordalert"
        self.subscription_id = None

    def run_test(self, name, method, endpoint, expected_status, data=None, token=None, is_admin=False):
        """Run a single API test"""
        url = f"{self.base_url}/api/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                if response.text:
                    try:
                        return success, response.json()
                    except:
                        return success, response.text
                return success, {}
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"Response: {response.text}")
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_health(self):
        """Test health endpoint"""
        return self.run_test("Health Check", "GET", "health", 200)

    def test_register_user(self):
        """Test user registration"""
        success, response = self.run_test(
            "User Registration",
            "POST",
            "register",
            200,
            data={"username": self.test_username, "password": self.test_password}
        )
        if success and 'access_token' in response:
            self.user_token = response['access_token']
            print(f"Registered user: {self.test_username}")
            return True
        return False

    def test_login_user(self):
        """Test user login"""
        success, response = self.run_test(
            "User Login",
            "POST",
            "login",
            200,
            data={"username": self.test_username, "password": self.test_password}
        )
        if success and 'access_token' in response:
            self.user_token = response['access_token']
            print(f"Logged in as user: {self.test_username}")
            return True
        return False

    def test_admin_login(self):
        """Test admin login"""
        success, response = self.run_test(
            "Admin Login",
            "POST",
            "admin/login",
            200,
            data={"username": self.admin_username, "password": self.admin_password}
        )
        if success and 'access_token' in response:
            self.admin_token = response['access_token']
            print(f"Logged in as admin: {self.admin_username}")
            return True
        return False

    def test_get_states(self):
        """Test getting states list"""
        return self.run_test("Get States", "GET", "states", 200)

    def test_get_counties(self):
        """Test getting counties for a state"""
        states = ["KY", "IN", "OH"]
        all_passed = True
        
        for state in states:
            success, response = self.run_test(f"Get Counties for {state}", "GET", f"counties/{state}", 200)
            if not success:
                all_passed = False
            else:
                print(f"Counties for {state}: {response.get('counties', [])}")
        
        return all_passed

    def test_subscribe_to_county(self):
        """Test subscribing to weather alerts for a county"""
        if not self.user_token:
            print("❌ Cannot test subscription - no user token")
            return False
            
        success, response = self.run_test(
            "Subscribe to County",
            "POST",
            "subscribe",
            200,
            data={"state": "KY", "counties": ["Jefferson", "Fayette"]},
            token=self.user_token
        )
        return success

    def test_get_subscriptions(self):
        """Test getting user subscriptions"""
        if not self.user_token:
            print("❌ Cannot test get subscriptions - no user token")
            return False
            
        success, response = self.run_test(
            "Get User Subscriptions",
            "GET",
            "my-subscriptions",
            200,
            token=self.user_token
        )
        
        if success and 'subscriptions' in response:
            subscriptions = response['subscriptions']
            if subscriptions:
                self.subscription_id = subscriptions[0]['id']
                print(f"Found {len(subscriptions)} subscriptions")
            return True
        return False

    def test_delete_subscription(self):
        """Test deleting a subscription"""
        if not self.user_token or not self.subscription_id:
            print("❌ Cannot test delete subscription - no user token or subscription ID")
            return False
            
        success, _ = self.run_test(
            "Delete Subscription",
            "DELETE",
            f"subscriptions/{self.subscription_id}",
            200,
            token=self.user_token
        )
        return success

    def test_get_alerts(self):
        """Test getting recent weather alerts"""
        success, response = self.run_test("Get Recent Alerts", "GET", "alerts", 200)
        if success:
            alerts = response.get('alerts', [])
            print(f"Found {len(alerts)} recent alerts")
        return success

    def test_admin_get_users(self):
        """Test admin getting all users"""
        if not self.admin_token:
            print("❌ Cannot test admin get users - no admin token")
            return False
            
        success, response = self.run_test(
            "Admin Get Users",
            "GET",
            "admin/users",
            200,
            token=self.admin_token,
            is_admin=True
        )
        
        if success:
            users = response.get('users', [])
            print(f"Found {len(users)} users")
        return success

    def test_admin_send_notification(self):
        """Test admin sending a notification"""
        if not self.admin_token:
            print("❌ Cannot test admin send notification - no admin token")
            return False
            
        success, _ = self.run_test(
            "Admin Send Normal Notification",
            "POST",
            "admin/notify",
            200,
            data={"message": "Test notification from API test", "is_critical": False},
            token=self.admin_token,
            is_admin=True
        )
        
        if success:
            success2, _ = self.run_test(
                "Admin Send Critical Notification",
                "POST",
                "admin/notify",
                200,
                data={"message": "CRITICAL Test notification from API test", "is_critical": True},
                token=self.admin_token,
                is_admin=True
            )
            return success2
        return False

    def test_admin_get_notifications(self):
        """Test admin getting notifications"""
        if not self.admin_token:
            print("❌ Cannot test admin get notifications - no admin token")
            return False
            
        success, response = self.run_test(
            "Admin Get Notifications",
            "GET",
            "admin/notifications",
            200,
            token=self.admin_token,
            is_admin=True
        )
        
        if success:
            notifications = response.get('notifications', [])
            print(f"Found {len(notifications)} notifications")
        return success

    def test_admin_get_stats(self):
        """Test admin getting stats"""
        if not self.admin_token:
            print("❌ Cannot test admin get stats - no admin token")
            return False
            
        success, response = self.run_test(
            "Admin Get Stats",
            "GET",
            "admin/stats",
            200,
            token=self.admin_token,
            is_admin=True
        )
        
        if success:
            print(f"Stats: {response}")
        return success

def main():
    print("🌩️ Weather Alert System API Test 🌩️")
    print("=" * 50)
    
    tester = WeatherAlertAPITester()
    
    # Basic health check
    tester.test_health()
    
    # Test user registration and login
    tester.test_register_user()
    
    # If registration failed, try login with existing user
    if not tester.user_token:
        tester.test_login_user()
    
    # Test admin login
    tester.test_admin_login()
    
    # Test getting states and counties
    tester.test_get_states()
    tester.test_get_counties()
    
    # Test weather alerts
    tester.test_get_alerts()
    
    # Test user subscription flow
    if tester.user_token:
        tester.test_subscribe_to_county()
        tester.test_get_subscriptions()
        if tester.subscription_id:
            tester.test_delete_subscription()
    
    # Test admin features
    if tester.admin_token:
        tester.test_admin_get_users()
        tester.test_admin_send_notification()
        tester.test_admin_get_notifications()
        tester.test_admin_get_stats()
    
    # Print results
    print("\n" + "=" * 50)
    print(f"📊 Tests passed: {tester.tests_passed}/{tester.tests_run}")
    print("=" * 50)
    
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())