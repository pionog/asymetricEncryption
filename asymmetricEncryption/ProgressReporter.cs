using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace asymmetricEncryption
{
    public class ProgressReporter
    {
        public delegate void ProgressChangedEventHandler(int progress);
        public event ProgressChangedEventHandler ProgressChanged;

        public async Task ReportProgress(int progress)
        {
            ProgressChanged?.Invoke(progress);
        }
    }
}
