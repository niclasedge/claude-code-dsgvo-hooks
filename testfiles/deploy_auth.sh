#!/bin/bash
export DB_PASSWORD="fake-password-for-testing"
export API_SECRET="fake-secret-for-testing"
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/deploy
