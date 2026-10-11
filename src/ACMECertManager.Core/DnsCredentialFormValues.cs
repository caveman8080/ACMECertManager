using System;
using System.Collections.Generic;

namespace ACMECertManager
{
    /// <summary>
    /// Decides what each DNS plugin credential input should show. Values only ever come from the
    /// credential the user explicitly selected under "Stored Credentials"; choosing
    /// "(use new/custom credentials)" (selected == null) always yields empty fields.
    /// </summary>
    public static class DnsCredentialFormValues
    {
        public static Dictionary<string, string> Resolve(
            IEnumerable<DnsCredentialField> fields,
            IReadOnlyDictionary<string, string>? selectedCredentialValues)
        {
            ArgumentNullException.ThrowIfNull(fields);

            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var field in fields)
            {
                var value = string.Empty;
                if (selectedCredentialValues is not null &&
                    selectedCredentialValues.TryGetValue(field.Name, out var stored) &&
                    stored is not null)
                {
                    value = stored;
                }

                result[field.Name] = value;
            }

            return result;
        }
    }
}
