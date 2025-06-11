import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class SymbolPasswordValidator:
    """
    تحقق من أن كلمة المرور تحتوي على رمز خاص واحد على الأقل.
    """
    def __init__(self, min_symbols=1):
        self.min_symbols = min_symbols
        self.symbols = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?]'

    def validate(self, password, user=None):
        if len(re.findall(self.symbols, password)) < self.min_symbols:
            raise ValidationError(
                _("يجب أن تحتوي كلمة المرور على %(min_symbols)d رمز خاص على الأقل."),
                code='password_no_symbol',
                params={'min_symbols': self.min_symbols},
            )

    def get_help_text(self):
        return _("يجب أن تحتوي كلمة المرور على {min_symbols} رمز خاص على الأقل (!@#$%^&* إلخ).").format(
            min_symbols=self.min_symbols
        ) 