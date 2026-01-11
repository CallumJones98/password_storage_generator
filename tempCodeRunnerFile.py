from main import PasswordGenerator

def test_passwordgen():
  pg = PasswordGenerator(10)
  password = pg.create()
  assert len(password) == 10
  
