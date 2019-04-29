type
  ModsecInvalidConfig* = object of Exception

func dequote*(str: string): string =
  if str[0] == '"' and str[^1] == '"':
    return str[1..^2]
  else:
    return str
