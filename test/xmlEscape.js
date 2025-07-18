let escape = {}

export  default  function xmlEscape(string, ignore) {
  var pattern;

  if (string === null || string === undefined) return;

  ignore = (ignore || '').replace(/[^&"<>\']/g, '');
  pattern = '([&"<>\'])'.replace(new RegExp('[' + ignore + ']', 'g'), '');

  return string.replace(new RegExp(pattern, 'g'), function(str, item) {
            return escape.map[item];
          })
}

escape.map = {
    '>': '&gt;'
  , '<': '&lt;'
  , "'": '&apos;'
  , '"': '&quot;'
  , '&': '&amp;'
}