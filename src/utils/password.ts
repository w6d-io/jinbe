/**
 * Password strength validation utility
 * Evaluates password complexity and provides feedback
 */
export class Password {
  public static requirements: Array<{ re: RegExp; label: string }> = [
    { re: /[0-9]/, label: 'Includes number' },
    { re: /[a-z]/, label: 'Includes lowercase letter' },
    { re: /[A-Z]/, label: 'Includes uppercase letter' },
    { re: /[$&+,:;=?@#|'<>.^*()%!-]/, label: 'Includes special symbol' },
  ]

  public static getStrength(password: string): number {
    let multiplier = password.length > 8 ? 0 : 1

    this.requirements.forEach((requirement) => {
      if (!requirement.re.test(password)) {
        multiplier += 1
      }
    })

    return Math.max(
      100 - (100 / (this.requirements.length + 1)) * multiplier,
      10
    )
  }

  public static validate(password: string): {
    isValid: boolean
    strength: number
    missing: string[]
  } {
    const missing = this.requirements
      .filter((req) => !req.re.test(password))
      .map((req) => req.label)

    return {
      isValid: password.length >= 8 && missing.length === 0,
      strength: this.getStrength(password),
      missing,
    }
  }
}
