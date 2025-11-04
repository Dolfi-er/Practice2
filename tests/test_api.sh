# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

BASE_URL="http://localhost:8000"

echo -e "${BLUE}=== Starting API Tests ===${NC}"

# Function to make API calls and handle responses
make_request() {
    local method=$1
    local url=$2
    local data=$3
    local token=$4
    local expected_success=${5:-true}  # default to true
    
    local curl_cmd="curl -s -X $method '$url' -H 'Content-Type: application/json'"
    
    if [ ! -z "$token" ]; then
        curl_cmd="$curl_cmd -H 'Authorization: Bearer $token'"
    fi
    
    if [ ! -z "$data" ]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi
    
    echo -e "${YELLOW}Request: $method $url${NC}"
    if [ ! -z "$data" ]; then
        echo -e "${YELLOW}Data: $data${NC}"
    fi
    
    local response=$(eval $curl_cmd)
    echo -e "${YELLOW}Response: $response${NC}"
    echo ""
    
    # Extract success status
    local success=$(echo $response | grep -o '"success":[^,]*' | cut -d':' -f2 | tr -d ' ')
    
    if [ "$success" = "$expected_success" ]; then
        echo -e "${GREEN}✓ Success (expected: $expected_success)${NC}"
        return 0
    else
        echo -e "${RED}✗ Failed (expected: $expected_success, got: $success)${NC}"
        return 1
    fi
}

# Wait for services to be ready
echo -e "${BLUE}Waiting for services to be ready...${NC}"
sleep 10

# Test 1: Health checks
echo -e "${BLUE}=== Health Checks ===${NC}"
make_request "GET" "$BASE_URL/health"

# Test 2: User Registration
echo -e "${BLUE}=== User Registration ===${NC}"
REGISTER_DATA='{
    "email": "testuser@example.com",
    "password": "password123",
    "name": "Test User"
}'
make_request "POST" "$BASE_URL/v1/users/register" "$REGISTER_DATA"

# Test 3: Duplicate Registration (Should Fail)
echo -e "${BLUE}=== Duplicate Registration (Should Fail) ===${NC}"
make_request "POST" "$BASE_URL/v1/users/register" "$REGISTER_DATA" "" "false"

# Test 4: User Login
echo -e "${BLUE}=== User Login ===${NC}"
LOGIN_DATA='{
    "email": "testuser@example.com",
    "password": "password123"
}'
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/users/login" \
    -H "Content-Type: application/json" \
    -d "$LOGIN_DATA")

echo "Login Response: $LOGIN_RESPONSE"

# Extract token from login response
TOKEN=$(echo $LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)
echo -e "${GREEN}User Token: $TOKEN${NC}"

if [ -z "$TOKEN" ]; then
    echo -e "${RED}Failed to get user token, stopping tests${NC}"
    exit 1
fi

# Test 5: Get User Profile
echo -e "${BLUE}=== Get User Profile ===${NC}"
make_request "GET" "$BASE_URL/v1/users/me" "" "$TOKEN"

# Test 6: Create Order for Authenticated User
echo -e "${BLUE}=== Create Order for Authenticated User ===${NC}"
ORDER_DATA='{
    "items": [
        {
            "product": "Laptop",
            "quantity": 1,
            "price": 999.99
        },
        {
            "product": "Mouse",
            "quantity": 2,
            "price": 25.50
        }
    ]
}'
ORDER_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/orders" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "$ORDER_DATA")

echo "Order Response: $ORDER_RESPONSE"

# Extract order ID and verify status is "created"
ORDER_ID=$(echo $ORDER_RESPONSE | grep -o '"id":"[^"]*' | cut -d'"' -f4)
ORDER_STATUS=$(echo $ORDER_RESPONSE | grep -o '"status":"[^"]*' | cut -d'"' -f4)

echo -e "${GREEN}Order ID: $ORDER_ID${NC}"
echo -e "${GREEN}Order Status: $ORDER_STATUS${NC}"

# Verify order was created successfully with "created" status
if [[ "$ORDER_RESPONSE" == *"\"success\":true"* ]] && [[ "$ORDER_STATUS" == "created" || "$ORDER_STATUS" == "pending" ]]; then
    echo -e "${GREEN}✓ Order created successfully with expected status${NC}"
else
    echo -e "${RED}✗ Order creation failed or wrong status${NC}"
fi

if [ ! -z "$ORDER_ID" ] && [ "$ORDER_ID" != "null" ]; then
    # Test 7: Get Own Order
    echo -e "${BLUE}=== Get Own Order ===${NC}"
    OWN_ORDER_RESPONSE=$(curl -s -X GET "$BASE_URL/v1/orders/$ORDER_ID" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "Own Order Response: $OWN_ORDER_RESPONSE"
    
    # Verify we can access our own order
    if [[ "$OWN_ORDER_RESPONSE" == *"\"success\":true"* ]] && [[ "$OWN_ORDER_RESPONSE" == *"$ORDER_ID"* ]]; then
        echo -e "${GREEN}✓ Successfully retrieved own order${NC}"
    else
        echo -e "${RED}✗ Failed to retrieve own order${NC}"
    fi

    # Test 8: Get User Orders List with Pagination
    echo -e "${BLUE}=== Get User Orders List with Pagination ===${NC}"
    ORDERS_LIST_RESPONSE=$(curl -s -X GET "$BASE_URL/v1/orders?page=1&limit=10" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "Orders List Response: $ORDERS_LIST_RESPONSE"
    
    # Check pagination fields and structure
    if [[ "$ORDERS_LIST_RESPONSE" == *"\"success\":true"* ]]; then
        echo -e "${GREEN}✓ Orders list retrieved successfully${NC}"
        
        # Check for pagination fields
        if [[ "$ORDERS_LIST_RESPONSE" == *"\"page\":"* ]] && [[ "$ORDERS_LIST_RESPONSE" == *"\"limit\":"* ]]; then
            echo -e "${GREEN}✓ Pagination fields present${NC}"
        else
            echo -e "${YELLOW}⚠ Pagination fields missing${NC}"
        fi
        
        # Check for orders array
        if [[ "$ORDERS_LIST_RESPONSE" == *"\"orders\":"* ]]; then
            echo -e "${GREEN}✓ Orders array present${NC}"
        else
            echo -e "${YELLOW}⚠ Orders array missing${NC}"
        fi
    else
        echo -e "${RED}✗ Failed to retrieve orders list${NC}"
    fi

    # Register second user for testing access control
    echo -e "${BLUE}=== Register Second User for Access Control Tests ===${NC}"
    SECOND_USER_DATA='{
        "email": "seconduser@example.com",
        "password": "password123",
        "name": "Second User"
    }'
    SECOND_USER_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/users/register" \
        -H "Content-Type: application/json" \
        -d "$SECOND_USER_DATA")
    
    echo "Second User Registration: $SECOND_USER_RESPONSE"
    
    # Login as second user
    SECOND_LOGIN_DATA='{
        "email": "seconduser@example.com",
        "password": "password123"
    }'
    SECOND_LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/users/login" \
        -H "Content-Type: application/json" \
        -d "$SECOND_LOGIN_DATA")
    
    SECOND_TOKEN=$(echo $SECOND_LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    echo -e "${GREEN}Second User Token: $SECOND_TOKEN${NC}"

    # Test 9: Attempt to Update Someone Else's Order (Should Fail)
    if [ ! -z "$SECOND_TOKEN" ]; then
        echo -e "${BLUE}=== Attempt to Update Someone Else's Order (Should Fail) ===${NC}"
        STATUS_DATA='{
            "status": "in_progress"
        }'
        make_request "PUT" "$BASE_URL/v1/orders/$ORDER_ID/status" "$STATUS_DATA" "$SECOND_TOKEN" "false"
    fi

    # Test 10: Cancel Own Order
    echo -e "${BLUE}=== Cancel Own Order ===${NC}"
    CANCEL_RESPONSE=$(curl -s -X PUT "$BASE_URL/v1/orders/$ORDER_ID/cancel" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "Cancel Response: $CANCEL_RESPONSE"
    
    # Verify cancellation was successful
    if [[ "$CANCEL_RESPONSE" == *"\"success\":true"* ]]; then
        echo -e "${GREEN}✓ Order cancelled successfully${NC}"
        
        # Check if status is "cancelled"
        CANCELLED_STATUS=$(echo $CANCEL_RESPONSE | grep -o '"status":"[^"]*' | cut -d'"' -f4)
        if [ "$CANCELLED_STATUS" = "cancelled" ]; then
            echo -e "${GREEN}✓ Order status correctly set to 'cancelled'${NC}"
        else
            echo -e "${YELLOW}⚠ Order status is '$CANCELLED_STATUS' instead of 'cancelled'${NC}"
        fi
        
        # Test 11: Verify Order Remains Accessible After Cancellation
        echo -e "${BLUE}=== Verify Order Remains Accessible After Cancellation ===${NC}"
        CANCELLED_ORDER_RESPONSE=$(curl -s -X GET "$BASE_URL/v1/orders/$ORDER_ID" \
            -H "Authorization: Bearer $TOKEN")
        
        if [[ "$CANCELLED_ORDER_RESPONSE" == *"\"success\":true"* ]] && [[ "$CANCELLED_ORDER_RESPONSE" == *"$ORDER_ID"* ]]; then
            echo -e "${GREEN}✓ Cancelled order remains accessible${NC}"
        else
            echo -e "${RED}✗ Cancelled order became inaccessible${NC}"
        fi
        
        # Test 12: Attempt to Cancel Already Cancelled Order (Should Fail)
        echo -e "${BLUE}=== Attempt to Cancel Already Cancelled Order (Should Fail) ===${NC}"
        make_request "PUT" "$BASE_URL/v1/orders/$ORDER_ID/cancel" "" "$TOKEN" "false"
        
    else
        echo -e "${RED}✗ Order cancellation failed${NC}"
    fi

else
    echo -e "${YELLOW}Order creation failed, skipping order-related tests${NC}"
fi

# Test 13: Admin Login and Tests
echo -e "${PURPLE}=== Admin Login ===${NC}"
ADMIN_LOGIN_DATA='{
    "email": "admin@test.com",
    "password": "admin123"
}'
ADMIN_LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/users/login" \
    -H "Content-Type: application/json" \
    -d "$ADMIN_LOGIN_DATA")

echo "Admin Login Response: $ADMIN_LOGIN_RESPONSE"

# Extract admin token
ADMIN_TOKEN=$(echo $ADMIN_LOGIN_RESPONSE | grep -o '"token":"[^"]*' | cut -d'"' -f4)
echo -e "${GREEN}Admin Token: $ADMIN_TOKEN${NC}"

if [ ! -z "$ADMIN_TOKEN" ]; then
    # Test 14: Admin Get All Users
    echo -e "${PURPLE}=== Admin: Get All Users ===${NC}"
    make_request "GET" "$BASE_URL/v1/users" "" "$ADMIN_TOKEN"

    # Test 15: Admin Get All Orders
    echo -e "${PURPLE}=== Admin: Get All Orders ===${NC}"
    make_request "GET" "$BASE_URL/v1/orders" "" "$ADMIN_TOKEN"
fi

# Test 16: Error Cases
echo -e "${BLUE}=== Testing Error Cases ===${NC}"

# Invalid registration data
echo -e "${YELLOW}Testing invalid registration...${NC}"
INVALID_REGISTER_DATA='{
    "email": "invalid-email",
    "password": "123",
    "name": "T"
}'
make_request "POST" "$BASE_URL/v1/users/register" "$INVALID_REGISTER_DATA" "" "false"

# Invalid login
echo -e "${YELLOW}Testing invalid login...${NC}"
INVALID_LOGIN_DATA='{
    "email": "nonexistent@example.com",
    "password": "wrongpassword"
}'
make_request "POST" "$BASE_URL/v1/users/login" "$INVALID_LOGIN_DATA" "" "false"

# Access without token
echo -e "${YELLOW}Testing access without token...${NC}"
make_request "GET" "$BASE_URL/v1/users/me" "" "" "false"

# Invalid order data
echo -e "${YELLOW}Testing invalid order creation...${NC}"
INVALID_ORDER_DATA='{
    "items": []
}'
make_request "POST" "$BASE_URL/v1/orders" "$INVALID_ORDER_DATA" "$TOKEN" "false"

# Test non-existent order
echo -e "${YELLOW}Testing access to non-existent order...${NC}"
make_request "GET" "$BASE_URL/v1/orders/nonexistent-order-id" "" "$TOKEN" "false"

echo -e "${GREEN}=== All tests completed ===${NC}"
