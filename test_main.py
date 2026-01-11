from main import PasswordGenerator
import random, string
import pytest

# Password Generator Class tests

def test_passwordgen():
  pg = PasswordGenerator(10)
  password = pg.create()
  assert len(password) == 10 #testing correct length of password e.g. 10 should return length of 10
  
@pytest.fixture
def pwd_gen():
  random_num = random.randint(6,20)
  pg = PasswordGenerator(random_num)
  return pg 

def test_passwordgen_specialchar(pwd_gen):
  pwd = pwd_gen.create()
  special_test = "!?/@#&"
  assert any(el in pwd for el in special_test) #testing password generated contains a special character e.g password12!

def test_passwordgen_normalchars(pwd_gen):
  pwd = pwd_gen.create()
  chars_test = string.ascii_letters
  assert any(el in pwd for el in chars_test) #testing password generated contains an element from string.ascii_letters e.g. p!?!##x!
