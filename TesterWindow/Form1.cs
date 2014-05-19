using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;



namespace TesterWindow
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private unsafe void Form1_Load(object sender, EventArgs e)
        {
            Tester.Launch(this.Handle);
            
        }

        protected override void WndProc(ref Message msg)
        {
            if (msg.Msg == 0x401)
            {
                msg.Result = (IntPtr)(Tester.OnMessage(this, (uint)msg.WParam.ToInt32(), msg.LParam.ToInt32()) ? 1 : 0);
            }
            else
            {
                base.WndProc(ref msg);
            }
        }
    }
}
